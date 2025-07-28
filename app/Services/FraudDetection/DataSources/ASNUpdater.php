<?php

namespace App\Services\FraudDetection\DataSources;

use App\Models\ASN;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class ASNUpdater
{
    protected array $sources = [
        'ripe' => [
            'url' => 'https://ftp.ripe.net/ripe/asnames/asn.txt',
            'format' => 'ripe',
        ],
        // Note: Removed compressed sources to avoid memory issues
        // Add back if needed with proper streaming decompression
    ];

    protected array $knownHostingProviders = [
        'amazon', 'aws', 'ec2', 'google cloud', 'gcp', 'azure', 'microsoft',
        'digitalocean', 'linode', 'vultr', 'ovh', 'hetzner', 'contabo',
        'alibaba cloud', 'oracle cloud', 'ibm cloud', 'scaleway', 'upcloud',
        'kamatera', 'hostinger', 'godaddy', 'namecheap', 'bluehost',
        'rackspace', 'softlayer', 'cloudflare', 'fastly', 'maxcdn',
    ];

    protected array $knownVpnProviders = [
        'nordvpn', 'expressvpn', 'surfshark', 'cyberghost', 'pia',
        'private internet access', 'protonvpn', 'mullvad', 'windscribe',
        'tunnelbear', 'hide.me', 'ipvanish', 'vyprvpn', 'purevpn',
        'zenmate', 'hotspot shield', 'ivacy', 'trust.zone', 'torguard',
    ];

    protected int $memoryLimit;

    protected int $batchSize = 500;

    public function __construct()
    {
        $memoryLimitString = ini_get('memory_limit');

        if ($memoryLimitString === '-1') {
            // Handle unlimited memory if needed, e.g., set a high default
            // For now, we'll just avoid calculation.
            // You might want to assign a large, but finite, number.
            $this->memoryLimit = PHP_INT_MAX;
        } else {
            $memoryInBytes = $this->convertShorthandToBytes($memoryLimitString);
            $this->memoryLimit = (int) ($memoryInBytes * 0.8);
        }
    }

    /**
     * Update ASN database from all sources.
     */
    public function updateAll(): array
    {
        ini_set('memory_limit', '512M');

        $results = [];
        $totalAsns = 0;

        Log::info('Starting ASN database update', [
            'memory_limit' => ini_get('memory_limit'),
            'initial_memory' => memory_get_usage(true),
        ]);

        foreach ($this->sources as $name => $config) {
            try {
                $count = $this->fetchAndProcessSource($name, $config);
                $results[$name] = [
                    'success' => true,
                    'count' => $count,
                ];
                $totalAsns += $count;

                Log::info("Processed ASN source: {$name}", [
                    'count' => $count,
                    'memory_usage' => memory_get_usage(true),
                ]);

                gc_collect_cycles();

            } catch (\Exception $e) {
                $results[$name] = [
                    'success' => false,
                    'error' => $e->getMessage(),
                ];
                Log::error("Failed to fetch ASN data from {$name}", [
                    'error' => $e->getMessage(),
                    'memory_usage' => memory_get_usage(true),
                ]);
            }
        }

        // Add some known high-risk ASNs manually
        $this->addKnownRiskyASNs();

        Log::info('ASN database update completed', [
            'total_asns' => $totalAsns,
            'peak_memory' => memory_get_peak_usage(true),
        ]);

        return [
            'sources' => $results,
            'total_asns' => $totalAsns,
        ];
    }

    /**
     * Fetch and process ASN data from a source.
     */
    protected function fetchAndProcessSource(string $name, array $config): int
    {
        $tempFile = tempnam(sys_get_temp_dir(), "asn_{$name}_");
        $processedCount = 0;

        try {
            // Download to temporary file
            $response = Http::timeout(120)->sink($tempFile)->get($config['url']);

            if (! $response->successful()) {
                throw new \Exception('HTTP request failed with status: '.$response->status());
            }

            // Process file line by line
            $handle = fopen($tempFile, 'r');
            if (! $handle) {
                throw new \Exception('Could not open temporary file');
            }

            $batch = [];

            while (($line = fgets($handle)) !== false) {
                // Skip comments and empty lines
                $line = trim($line);
                if (empty($line) || str_starts_with($line, '#')) {
                    continue;
                }

                $asnData = $this->parseAsnLine($line, $config['format']);
                if ($asnData) {
                    $batch[] = $asnData;

                    if (count($batch) >= $this->batchSize) {
                        $this->processAsnBatch($batch);
                        $processedCount += count($batch);
                        $batch = [];

                        // Periodic memory management
                        if ($processedCount % 5000 === 0) {
                            gc_collect_cycles();

                            if (memory_get_usage() > $this->memoryLimit) {
                                Log::warning('High memory usage during ASN processing', [
                                    'memory_usage' => memory_get_usage(true),
                                    'processed' => $processedCount,
                                ]);
                            }
                        }
                    }
                }
            }

            // Process remaining ASNs
            if (! empty($batch)) {
                $this->processAsnBatch($batch);
                $processedCount += count($batch);
            }

            fclose($handle);

        } finally {
            @unlink($tempFile);
        }

        return $processedCount;
    }

    /**
     * Parse an ASN line based on format.
     */
    protected function parseAsnLine(string $line, string $format): ?array
    {
        // Format: ASN, Country, Organization
        if ($format == 'ripe') {
            if (preg_match('/^(\d+)\s+(\w{2})\s+(.+)$/', $line, $matches)) {
                return [
                    'asn' => (int) $matches[1],
                    'country_code' => $matches[2],
                    'organization' => trim($matches[3]),
                ];
            }
        }

        return null;
    }

    /**
     * Process a batch of ASNs.
     */
    protected function processAsnBatch(array $asns): void
    {
        Log::info('Processing ASN batch', [
            'count' => count($asns),
            'memory_usage' => memory_get_usage(true),
        ]);
        if (empty($asns)) {
            return;
        }

        $data = [];
        $now = now();

        foreach ($asns as $asn) {
            $org = strtolower($asn['organization'] ?? '');
            $type = $this->determineAsnType($org);

            $data[] = [
                'asn' => $asn['asn'],
                'name' => "AS{$asn['asn']}",
                'organization' => $asn['organization'] ?? 'Unknown',
                'country_code' => substr($asn['country_code'] ?? '', 0, 2),
                'type' => $type,
                'risk_weight' => $this->calculateRiskWeight($org, $type),
                'is_hosting' => $this->isHostingProvider($org),
                'is_vpn' => $this->isVpnProvider($org),
                'is_proxy' => $this->isProxyProvider($org),
                'ip_ranges' => null, // Will be populated separately if needed
                'verified_at' => $now,
                'created_at' => $now,
                'updated_at' => $now,
            ];
        }
        // Use upsert for efficient bulk operations
        ASN::upsert(
            $data,
            ['asn'], // Unique key
            ['name', 'organization', 'country_code', 'type', 'risk_weight',
                'is_hosting', 'is_vpn', 'is_proxy', 'verified_at', 'updated_at']
        );

        // Clear data array from memory
        unset($data);
    }

    /**
     * Determine ASN type based on organization name.
     */
    protected function determineAsnType(string $org): string
    {
        // Datacenter/Hosting
        if ($this->containsAny($org, ['hosting', 'cloud', 'server', 'datacenter', 'vps', 'dedicated', 'colocation'])) {
            return 'datacenter';
        }

        // ISP/Telecom
        if ($this->containsAny($org, ['telecom', 'communications', 'broadband', 'cable', 'dsl', 'fiber', 'wireless', 'internet'])) {
            return 'residential';
        }

        // Mobile carriers
        if ($this->containsAny($org, ['mobile', 'cellular', '4g', '5g', 'lte', 'gsm', 'cdma'])) {
            return 'mobile';
        }

        // Educational institutions
        if ($this->containsAny($org, ['university', 'college', 'education', 'academic', 'school', 'institute'])) {
            return 'education';
        }

        // Government/Military
        if ($this->containsAny($org, ['government', 'federal', 'military', 'defense', 'ministry', 'dept'])) {
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
     * Check if organization is a proxy provider.
     */
    protected function isProxyProvider(string $org): bool
    {
        $proxyKeywords = ['proxy', 'anonymizer', 'hide', 'mask', 'tunnel'];

        return $this->containsAny($org, $proxyKeywords);
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
    protected function calculateRiskWeight(string $org, string $type): int
    {
        $weight = 0;

        // Base weight by type
        $weight += match ($type) {
            'datacenter' => 30,
            'mobile' => 10,
            'education' => 5,
            'government' => 0,
            default => 0,
        };

        // Additional weight for specific services
        if ($this->isVpnProvider($org)) {
            $weight += 40;
        }

        if ($this->isProxyProvider($org)) {
            $weight += 40;
        }

        // High-risk hosting providers
        $highRiskHosting = ['bulletproof', 'offshore', 'anonymous'];
        if ($this->containsAny($org, $highRiskHosting)) {
            $weight += 50;
        }

        return min($weight, 100);
    }

    /**
     * Add known high-risk ASNs manually.
     */
    protected function addKnownRiskyASNs(): void
    {
        $riskyAsns = [
            // Add known problematic ASNs here
            // Example format:
            // ['asn' => 12345, 'organization' => 'Bad Hosting Inc', 'risk_weight' => 90],
        ];

        if (! empty($riskyAsns)) {
            $this->processAsnBatch($riskyAsns);
        }
    }

    /**
     * Converts a shorthand byte value string (e.g., 256M, 1G) to bytes.
     */
    private function convertShorthandToBytes(string $shorthand): int
    {
        $shorthand = strtolower(trim($shorthand));
        $value = (int) $shorthand;

        switch (substr($shorthand, -1)) {
            case 'g':
                $value *= 1024;
                // fallthrough
            case 'm':
                $value *= 1024;
                // fallthrough
            case 'k':
                $value *= 1024;
        }

        return $value;
    }
}
