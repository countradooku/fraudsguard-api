<?php

namespace App\Services\FraudDetection\DataSources;

use App\Models\ASN;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;

class ASNUpdater
{
    protected array $sources = [
        'ripe' => [
            'url' => 'https://ftp.ripe.net/ripe/asnames/asn.txt',
            'format' => 'ripe',
        ],
        'iptoasn' => [
            'url' => 'https://iptoasn.com/data/ip2asn-combined.tsv.gz',
            'format' => 'iptoasn',
            'compressed' => true,
        ],
    ];

    protected array $knownHostingProviders = [
        'amazon', 'aws', 'ec2', 'google cloud', 'gcp', 'azure', 'microsoft',
        'digitalocean', 'linode', 'vultr', 'ovh', 'hetzner', 'contabo',
        'alibaba cloud', 'oracle cloud', 'ibm cloud', 'scaleway', 'upcloud',
        'kamatera', 'vultr', 'hostinger', 'godaddy', 'namecheap', 'bluehost',
    ];

    protected array $knownVpnProviders = [
        'nordvpn', 'expressvpn', 'surfshark', 'cyberghost', 'pia', 'private internet access',
        'protonvpn', 'mullvad', 'windscribe', 'tunnelbear', 'hide.me', 'ipvanish',
        'vyprvpn', 'purevpn', 'zenmate', 'hotspot shield', 'ivacy',
    ];

    /**
     * Update ASN database from all sources.
     */
    public function updateAll(): array
    {
        $results = [];
        $allAsns = [];

        foreach ($this->sources as $name => $config) {
            try {
                $asns = $this->fetchFromSource($name, $config);
                $results[$name] = [
                    'success' => true,
                    'count' => count($asns),
                ];
                $allAsns = array_merge($allAsns, $asns);
            } catch (\Exception $e) {
                $results[$name] = [
                    'success' => false,
                    'error' => $e->getMessage(),
                ];
                Log::error("Failed to fetch ASN data from {$name}", [
                    'error' => $e->getMessage(),
                ]);
            }
        }

        // Merge and deduplicate by ASN number
        $mergedAsns = $this->mergeAsnData($allAsns);

        // Classify ASNs
        $classifiedAsns = $this->classifyAsns($mergedAsns);

        // Update database
        $this->updateDatabase($classifiedAsns);

        // Update IP ranges if available
        $this->updateIpRanges($classifiedAsns);

        return [
            'sources' => $results,
            'total_asns' => count($classifiedAsns),
        ];
    }

    /**
     * Fetch ASN data from a specific source.
     */
    protected function fetchFromSource(string $name, array $config): array
    {
        if ($config['compressed'] ?? false) {
            return $this->fetchCompressedSource($config['url'], $config['format']);
        }

        $response = Http::timeout(60)->get($config['url']);

        if (!$response->successful()) {
            throw new \Exception("HTTP request failed with status: " . $response->status());
        }

        switch ($config['format']) {
            case 'ripe':
                return $this->parseRipeFormat($response->body());
            case 'iptoasn':
                return $this->parseIpToAsnFormat($response->body());
            default:
                return [];
        }
    }

    /**
     * Fetch and decompress compressed sources.
     */
    protected function fetchCompressedSource(string $url, string $format): array
    {
        $tempFile = tempnam(sys_get_temp_dir(), 'asn_');

        try {
            // Download file
            $response = Http::timeout(120)->sink($tempFile)->get($url);

            if (!$response->successful()) {
                throw new \Exception("Failed to download file");
            }

            // Decompress
            $content = '';
            if (str_ends_with($url, '.gz')) {
                $content = gzdecode(file_get_contents($tempFile));
            } elseif (str_ends_with($url, '.zip')) {
                $zip = new \ZipArchive();
                if ($zip->open($tempFile) === true) {
                    $content = $zip->getFromIndex(0);
                    $zip->close();
                }
            }

            // Parse content
            switch ($format) {
                case 'iptoasn':
                    return $this->parseIpToAsnFormat($content);
                default:
                    return [];
            }
        } finally {
            @unlink($tempFile);
        }
    }

    /**
     * Parse RIPE ASN format.
     */
    protected function parseRipeFormat(string $content): array
    {
        $asns = [];
        $lines = explode("\n", $content);

        foreach ($lines as $line) {
            if (empty($line) || str_starts_with($line, '#')) {
                continue;
            }

            // Format: ASN, Country, Organization
            if (preg_match('/^(\d+)\s+(\w{2})\s+(.+)$/', $line, $matches)) {
                $asns[] = [
                    'asn' => (int) $matches[1],
                    'country_code' => $matches[2],
                    'organization' => trim($matches[3]),
                ];
            }
        }

        return $asns;
    }

    /**
     * Parse IP to ASN format (TSV).
     */
    protected function parseIpToAsnFormat(string $content): array
    {
        $asns = [];
        $lines = explode("\n", $content);
        $asnData = [];

        foreach ($lines as $line) {
            if (empty($line)) {
                continue;
            }

            $parts = explode("\t", $line);
            if (count($parts) >= 5) {
                $asn = (int) $parts[2];
                $country = $parts[3];
                $organization = $parts[4];

                if (!isset($asnData[$asn])) {
                    $asnData[$asn] = [
                        'asn' => $asn,
                        'country_code' => $country,
                        'organization' => $organization,
                        'ip_ranges' => [],
                    ];
                }

                // Add IP range
                $asnData[$asn]['ip_ranges'][] = $parts[0] . '/' . $this->calculateCidr($parts[0], $parts[1]);
            }
        }

        return array_values($asnData);
    }

    /**
     * Calculate CIDR from start and end IP.
     */
    protected function calculateCidr(string $startIp, string $endIp): int
    {
        $start = ip2long($startIp);
        $end = ip2long($endIp);

        if ($start === false || $end === false) {
            return 32; // Default to /32
        }

        $diff = $end - $start + 1;
        return 32 - (int) log($diff, 2);
    }

    /**
     * Merge ASN data from multiple sources.
     */
    protected function mergeAsnData(array $allAsns): array
    {
        $merged = [];

        foreach ($allAsns as $asn) {
            $key = $asn['asn'];

            if (!isset($merged[$key])) {
                $merged[$key] = $asn;
            } else {
                // Merge data, preferring non-empty values
                if (empty($merged[$key]['organization']) && !empty($asn['organization'])) {
                    $merged[$key]['organization'] = $asn['organization'];
                }
                if (empty($merged[$key]['country_code']) && !empty($asn['country_code'])) {
                    $merged[$key]['country_code'] = $asn['country_code'];
                }
                if (!empty($asn['ip_ranges'])) {
                    $merged[$key]['ip_ranges'] = array_merge(
                        $merged[$key]['ip_ranges'] ?? [],
                        $asn['ip_ranges']
                    );
                }
            }
        }

        return array_values($merged);
    }

    /**
     * Classify ASNs by type.
     */
    protected function classifyAsns(array $asns): array
    {
        foreach ($asns as &$asn) {
            $org = strtolower($asn['organization'] ?? '');
            $name = "AS{$asn['asn']}";

            // Determine type
            $asn['type'] = $this->determineAsnType($org);

            // Check if hosting provider
            $asn['is_hosting'] = $this->isHostingProvider($org);

            // Check if VPN provider
            $asn['is_vpn'] = $this->isVpnProvider($org);

            // Calculate risk weight
            $asn['risk_weight'] = $this->calculateRiskWeight($asn);

            // Set name
            $asn['name'] = $name;
        }

        return $asns;
    }

    /**
     * Determine ASN type based on organization name.
     */
    protected function determineAsnType(string $org): string
    {
        // Check for hosting/datacenter
        if ($this->containsAny($org, ['hosting', 'cloud', 'server', 'datacenter', 'vps', 'dedicated'])) {
            return 'datacenter';
        }

        // Check for ISP/Telecom
        if ($this->containsAny($org, ['telecom', 'communications', 'broadband', 'cable', 'dsl', 'fiber', 'wireless'])) {
            return 'residential';
        }

        // Check for mobile
        if ($this->containsAny($org, ['mobile', 'cellular', '4g', '5g', 'lte'])) {
            return 'mobile';
        }

        // Check for education
        if ($this->containsAny($org, ['university', 'college', 'education', 'academic', 'school'])) {
            return 'education';
        }

        // Check for government
        if ($this->containsAny($org, ['government', 'federal', 'military', 'defense'])) {
            return 'government';
        }

        return 'unknown';
    }

    /**
     * Check if organization is a hosting provider.
     */
    protected function isHostingProvider(string $org): bool
    {
        return $this->containsAny($org, $this->knownHostingProviders);
    }

    /**
     * Check if organization is a VPN provider.
     */
    protected function isVpnProvider(string $org): bool
    {
        return $this->containsAny($org, $this->knownVpnProviders);
    }

    /**
     * Check if string contains any of the needles.
     */
    protected function containsAny(string $haystack, array $needles): bool
    {
        foreach ($needles as $needle) {
            if (str_contains($haystack, $needle)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Calculate risk weight for ASN.
     */
    protected function calculateRiskWeight(array $asn): int
    {
        $weight = 0;

        // Base weight by type
        switch ($asn['type']) {
            case 'datacenter':
                $weight += 30;
                break;
            case 'mobile':
                $weight += 10;
                break;
            case 'education':
                $weight += 5;
                break;
            case 'government':
                $weight += 0;
                break;
            case 'residential':
            default:
                $weight += 0;
        }

        // Additional weight for VPN/Proxy
        if ($asn['is_vpn']) {
            $weight += 40;
        }

        if ($asn['is_proxy'] ?? false) {
            $weight += 40;
        }

        // High-risk countries (example)
        $highRiskCountries = ['XX', 'YY']; // Replace with actual codes
        if (in_array($asn['country_code'] ?? '', $highRiskCountries)) {
            $weight += 20;
        }

        return min($weight, 100);
    }

    /**
     * Update database with ASN data.
     */
    protected function updateDatabase(array $asns): void
    {
        DB::transaction(function () use ($asns) {
            // Process in chunks
            $chunks = array_chunk($asns, 500);

            foreach ($chunks as $chunk) {
                $data = [];

                foreach ($chunk as $asn) {
                    $data[] = [
                        'asn' => $asn['asn'],
                        'name' => $asn['name'],
                        'organization' => $asn['organization'] ?? 'Unknown',
                        'country_code' => substr($asn['country_code'] ?? '', 0, 2),
                        'type' => $asn['type'],
                        'risk_weight' => $asn['risk_weight'],
                        'is_hosting' => $asn['is_hosting'],
                        'is_vpn' => $asn['is_vpn'],
                        'is_proxy' => $asn['is_proxy'] ?? false,
                        'ip_ranges' => !empty($asn['ip_ranges']) ? json_encode($asn['ip_ranges']) : null,
                        'verified_at' => now(),
                        'created_at' => now(),
                        'updated_at' => now(),
                    ];
                }

                ASN::upsert(
                    $data,
                    ['asn'], // Unique key
                    ['name', 'organization', 'country_code', 'type', 'risk_weight',
                        'is_hosting', 'is_vpn', 'is_proxy', 'ip_ranges', 'verified_at', 'updated_at']
                );
            }
        });
    }

    /**
     * Update IP ranges for ASNs.
     */
    protected function updateIpRanges(array $asns): void
    {
        // This would be implemented if we have a separate IP range table
        // or need to process IP ranges differently
    }
}
