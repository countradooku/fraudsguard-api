<?php

namespace App\Services\FraudDetection\Checks;

use App\Models\ASN;
use App\Models\BlacklistedIP;
use App\Models\TorExitNode;
use App\Services\HashingService;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

class IPCheck implements CheckInterface
{
    protected HashingService $hasher;

    // RFC 5735 reserved ranges
    protected array $reservedRanges = [
        '0.0.0.0/8',          // "This" network
        '10.0.0.0/8',         // Private-use
        '127.0.0.0/8',        // Loopback
        '169.254.0.0/16',     // Link local
        '172.16.0.0/12',      // Private-use
        '192.168.0.0/16',     // Private-use
        '224.0.0.0/4',        // Multicast
        '240.0.0.0/4',        // Reserved
        '255.255.255.255/32', // Broadcast
    ];

    public function __construct(HashingService $hasher)
    {
        $this->hasher = $hasher;
    }

    public function applicable(array $data): bool
    {
        return ! empty($data['ip']);
    }

    public function perform(array $data): array
    {
        $ip = trim($data['ip']);
        $details = [];
        $score = 0;
        $passed = true;

        // Validate IP format
        if (! filter_var($ip, FILTER_VALIDATE_IP)) {
            return [
                'passed' => false,
                'score' => 100,
                'details' => ['error' => 'Invalid IP format'],
            ];
        }

        $ipVersion = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 'v4' : 'v6';
        $details['ip_version'] = $ipVersion;

        // 1. Check if blacklisted
        if ($this->isBlacklisted($ip)) {
            $details['blacklisted'] = true;
            $score += 100;
            $passed = false;
        }

        // 2. RFC 5735 reserved range check
        if ($this->isReservedIP($ip)) {
            $details['reserved_range'] = true;
            $score += 100;
            $passed = false;

            return [
                'passed' => $passed,
                'score' => $score,
                'details' => $details,
            ];
        }

        // 3. Tor exit node detection
        if ($this->isTorExitNode($ip)) {
            $details['tor_exit_node'] = true;
            $score += 90;
            $passed = false;
        }

        // 4. Get ASN information
        $asnInfo = $this->getASNInfo($ip);
        if ($asnInfo) {
            $details['asn'] = $asnInfo;
            $score += $asnInfo['risk_score'];

            // 5. IP type classification
            if ($asnInfo['type'] === 'datacenter') {
                $details['datacenter_ip'] = true;
                $score += 30;
            } elseif ($asnInfo['type'] === 'residential') {
                $details['residential_ip'] = true;
                // Residential IPs are generally lower risk
            }

            // Check for VPN/Proxy
            if ($asnInfo['is_vpn'] || $asnInfo['is_proxy']) {
                $details['vpn_proxy'] = true;
                $score += 40;
            }
        }

        // 6. Geolocation consistency (if location data provided)
        if (! empty($data['country']) || ! empty($data['timezone'])) {
            $geoCheck = $this->checkGeolocationConsistency($ip, $data);
            $details['geo_consistency'] = $geoCheck;
            $score += $geoCheck['risk_score'];
        }

        // 7. Check velocity - multiple requests from same IP
        $velocityCheck = $this->checkVelocity($ip);
        if ($velocityCheck) {
            $details['velocity'] = $velocityCheck;
            $score += $velocityCheck['risk_score'];
        }

        // 8. Check proxy headers
        if (! empty($data['headers'])) {
            $proxyCheck = $this->checkProxyHeaders($data['headers'], $ip);
            $details['proxy_headers'] = $proxyCheck;
            $score += $proxyCheck['risk_score'];
        }

        // Cap score at 100
        $score = min($score, 100);

        // If score is too high, mark as failed
        if ($score >= 80) {
            $passed = false;
        }

        return [
            'passed' => $passed,
            'score' => $score,
            'details' => $details,
        ];
    }

    protected function isBlacklisted(string $ip): bool
    {
        $hash = $this->hasher->hash($ip);

        return Cache::remember("blacklist:ip:{$hash}", 300, function () use ($ip, $hash) {
            return BlacklistedIP::where('ip_hash', $hash)
                ->orWhere('ip_address', $ip)
                ->exists();
        });
    }

    protected function isReservedIP(string $ip): bool
    {
        foreach ($this->reservedRanges as $range) {
            if ($this->ipInRange($ip, $range)) {
                return true;
            }
        }

        return false;
    }

    protected function isTorExitNode(string $ip): bool
    {
        return Cache::remember("tor:ip:{$ip}", 3600, function () use ($ip) {
            return TorExitNode::where('ip_address', $ip)
                ->where('is_active', true)
                ->exists();
        });
    }

    protected function getASNInfo(string $ip): ?array
    {
        // First, try to get ASN from IP
        $asn = $this->getASNFromIP($ip);

        if (! $asn) {
            return null;
        }

        return Cache::remember("asn:info:{$asn}", 3600, function () use ($asn) {
            $asnRecord = ASN::where('asn', $asn)->first();

            if (! $asnRecord) {
                // Try to fetch from external service
                $asnRecord = $this->fetchASNInfo($asn);
            }

            if (! $asnRecord) {
                return null;
            }

            $riskScore = $asnRecord->risk_weight;

            return [
                'asn' => $asnRecord->asn,
                'name' => $asnRecord->name,
                'organization' => $asnRecord->organization,
                'country' => $asnRecord->country_code,
                'type' => $asnRecord->type,
                'is_hosting' => $asnRecord->is_hosting,
                'is_vpn' => $asnRecord->is_vpn,
                'is_proxy' => $asnRecord->is_proxy,
                'risk_score' => $riskScore,
            ];
        });
    }

    protected function getASNFromIP(string $ip): ?int
    {
        // This would use BGP data or an external service
        // For now, check if IP is in known ASN ranges

        $asns = ASN::whereNotNull('ip_ranges')->get();

        foreach ($asns as $asn) {
            $ranges = json_decode($asn->ip_ranges, true) ?? [];
            foreach ($ranges as $range) {
                if ($this->ipInRange($ip, $range)) {
                    return $asn->asn;
                }
            }
        }

        // Fallback to external service
        try {
            $response = Http::timeout(2)->get("https://ipapi.co/{$ip}/asn/");
            if ($response->successful()) {
                return (int) str_replace('AS', '', $response->body());
            }
        } catch (\Exception $e) {
            // Log error
        }

        return null;
    }

    protected function fetchASNInfo(int $asn): ?ASN
    {
        // Fetch ASN info from external source
        try {
            $response = Http::timeout(3)->get("https://ipapi.co/asn/{$asn}/json/");

            if ($response->successful()) {
                $data = $response->json();

                return ASN::create([
                    'asn' => $asn,
                    'name' => $data['name'] ?? 'Unknown',
                    'organization' => $data['domain'] ?? null,
                    'country_code' => $data['country'] ?? null,
                    'type' => $this->determineASNType($data),
                    'is_hosting' => $this->isHostingASN($data),
                    'is_vpn' => false, // Would need additional check
                    'is_proxy' => false, // Would need additional check
                    'risk_weight' => $this->calculateASNRiskWeight($data),
                ]);
            }
        } catch (\Exception $e) {
            // Log error
        }

        return null;
    }

    protected function checkGeolocationConsistency(string $ip, array $data): array
    {
        try {
            // Get IP geolocation
            $response = Http::timeout(2)->get("https://ipapi.co/{$ip}/json/");

            if (! $response->successful()) {
                return ['risk_score' => 0];
            }

            $ipGeo = $response->json();
            $riskScore = 0;
            $details = [];

            // Check country consistency
            if (! empty($data['country']) && ! empty($ipGeo['country_code'])) {
                if (strtoupper($data['country']) !== strtoupper($ipGeo['country_code'])) {
                    $details['country_mismatch'] = true;
                    $riskScore += 30;
                }
            }

            // Check timezone consistency
            if (! empty($data['timezone']) && ! empty($ipGeo['timezone'])) {
                if ($data['timezone'] !== $ipGeo['timezone']) {
                    // Allow for nearby timezones
                    $timezoneOffset = abs(
                        timezone_offset_get(
                            timezone_open($data['timezone']),
                            new \DateTime
                        ) - timezone_offset_get(
                            timezone_open($ipGeo['timezone']),
                            new \DateTime
                        )
                    ) / 3600;

                    if ($timezoneOffset > 3) {
                        $details['timezone_mismatch'] = true;
                        $riskScore += 20;
                    }
                }
            }

            $details['risk_score'] = $riskScore;

            return $details;

        } catch (\Exception $e) {
            return ['risk_score' => 0];
        }
    }

    protected function checkVelocity(string $ip): ?array
    {
        $key = "velocity:ip:{$ip}";
        $count = Cache::get($key, 0);

        // Increment counter
        Cache::put($key, $count + 1, now()->addHour());

        if ($count === 0) {
            return null;
        }

        $riskScore = 0;
        $details = ['requests_per_hour' => $count + 1];

        if ($count > 10) {
            $riskScore += 10;
        }
        if ($count > 50) {
            $riskScore += 20;
        }
        if ($count > 100) {
            $riskScore += 30;
        }

        $details['risk_score'] = $riskScore;

        return $details;
    }

    protected function checkProxyHeaders(array $headers, string $reportedIP): array
    {
        $proxyHeaders = [
            'X-Forwarded-For',
            'X-Real-IP',
            'X-Originating-IP',
            'X-Forwarded',
            'X-Cluster-Client-IP',
            'Forwarded-For',
            'Forwarded',
            'Via',
            'True-Client-IP',
            'CF-Connecting-IP', // Cloudflare
        ];

        $foundHeaders = [];
        $riskScore = 0;

        foreach ($proxyHeaders as $header) {
            $headerKey = strtolower(str_replace('-', '_', $header));
            if (! empty($headers[$headerKey])) {
                $foundHeaders[$header] = $headers[$headerKey];

                // Extract IPs from header
                $headerIPs = $this->extractIPsFromHeader($headers[$headerKey]);

                // Check if reported IP matches any in the chain
                if (! in_array($reportedIP, $headerIPs)) {
                    $riskScore += 20;
                }
            }
        }

        if (! empty($foundHeaders)) {
            $riskScore += 10; // Base score for using proxy
        }

        return [
            'headers_found' => $foundHeaders,
            'risk_score' => $riskScore,
        ];
    }

    protected function ipInRange(string $ip, string $range): bool
    {
        if (strpos($range, '/') === false) {
            return $ip === $range;
        }

        [$subnet, $mask] = explode('/', $range);

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $this->ipv4InRange($ip, $subnet, $mask);
        } else {
            return $this->ipv6InRange($ip, $subnet, $mask);
        }
    }

    protected function ipv4InRange(string $ip, string $subnet, int $mask): bool
    {
        $ip = ip2long($ip);
        $subnet = ip2long($subnet);
        $netmask = -1 << (32 - $mask);
        $subnet &= $netmask;

        return ($ip & $netmask) === $subnet;
    }

    protected function ipv6InRange(string $ip, string $subnet, int $mask): bool
    {
        $ipBin = inet_pton($ip);
        $subnetBin = inet_pton($subnet);

        $ipBits = '';
        $subnetBits = '';

        for ($i = 0; $i < strlen($ipBin); $i++) {
            $ipBits .= str_pad(decbin(ord($ipBin[$i])), 8, '0', STR_PAD_LEFT);
            $subnetBits .= str_pad(decbin(ord($subnetBin[$i])), 8, '0', STR_PAD_LEFT);
        }

        return substr($ipBits, 0, $mask) === substr($subnetBits, 0, $mask);
    }

    protected function extractIPsFromHeader(string $header): array
    {
        $ips = [];
        $parts = array_map('trim', explode(',', $header));

        foreach ($parts as $part) {
            if (filter_var($part, FILTER_VALIDATE_IP)) {
                $ips[] = $part;
            }
        }

        return $ips;
    }

    protected function determineASNType(array $data): string
    {
        $name = strtolower($data['name'] ?? '');
        $org = strtolower($data['domain'] ?? '');

        $hostingKeywords = ['hosting', 'cloud', 'vps', 'dedicated', 'server', 'datacenter', 'colocation'];
        $mobileKeywords = ['mobile', 'cellular', 'wireless', 'telecom', '4g', '5g', 'lte'];
        $educationKeywords = ['university', 'college', 'education', 'academic', 'school'];
        $governmentKeywords = ['government', 'federal', 'state', 'military', '.gov'];

        foreach ($hostingKeywords as $keyword) {
            if (str_contains($name, $keyword) || str_contains($org, $keyword)) {
                return 'datacenter';
            }
        }

        foreach ($mobileKeywords as $keyword) {
            if (str_contains($name, $keyword) || str_contains($org, $keyword)) {
                return 'mobile';
            }
        }

        foreach ($educationKeywords as $keyword) {
            if (str_contains($name, $keyword) || str_contains($org, $keyword)) {
                return 'education';
            }
        }

        foreach ($governmentKeywords as $keyword) {
            if (str_contains($name, $keyword) || str_contains($org, $keyword)) {
                return 'government';
            }
        }

        return 'residential'; // Default assumption
    }

    protected function isHostingASN(array $data): bool
    {
        return $this->determineASNType($data) === 'datacenter';
    }

    protected function calculateASNRiskWeight(array $data): int
    {
        $type = $this->determineASNType($data);

        switch ($type) {
            case 'datacenter':
                return 30;
            case 'mobile':
                return 10;
            case 'education':
                return 5;
            case 'government':
                return 0;
            case 'residential':
            default:
                return 0;
        }
    }
}
