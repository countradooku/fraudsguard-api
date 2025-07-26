<?php

namespace App\Services\FraudDetection\Checks;

use App\Models\FraudCheck;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

class DomainCheck implements CheckInterface
{
    public function applicable(array $data): bool
    {
        return ! empty($data['domain']) || (! empty($data['email']) && str_contains($data['email'], '@'));
    }

    public function perform(array $data): array
    {
        // Extract domain from email if not provided directly
        $domain = $data['domain'] ?? null;
        if (! $domain && ! empty($data['email']) && str_contains($data['email'], '@')) {
            [, $domain] = explode('@', $data['email']);
        }

        if (! $domain) {
            return [
                'passed' => false,
                'score' => 0,
                'details' => ['error' => 'No domain to check'],
            ];
        }

        $domain = strtolower(trim($domain));
        $details = [];
        $score = 0;
        $passed = true;

        // 1. RFC 1035 hostname validation
        if (! $this->isValidHostname($domain)) {
            $details['hostname_validation'] = 'failed';
            $score += 100;
            $passed = false;

            return [
                'passed' => $passed,
                'score' => $score,
                'details' => $details,
            ];
        }
        $details['hostname_validation'] = 'passed';

        // 2. MX record check
        $mxCheck = $this->checkMXRecords($domain);
        $details['mx_records'] = $mxCheck;
        if (! $mxCheck['exists']) {
            $score += 50;
            $passed = false;
        }

        // 3. Domain age verification
        $domainAge = $this->checkDomainAge($domain);
        if ($domainAge !== null) {
            $details['domain_age'] = $domainAge;

            if ($domainAge['days'] < 30) {
                $score += 40; // Very new domain
            } elseif ($domainAge['days'] < 180) {
                $score += 20; // Relatively new domain
            }
        }

        // 4. Check if parked/for sale
        if ($this->isParkedDomain($domain)) {
            $details['parked_domain'] = true;
            $score += 60;
            $passed = false;
        }

        // 5. Check DNS configuration
        $dnsCheck = $this->checkDNSConfiguration($domain);
        $details['dns_configuration'] = $dnsCheck;
        $score += $dnsCheck['risk_score'];

        // 6. Check domain reputation
        $reputation = $this->checkDomainReputation($domain);
        if ($reputation) {
            $details['reputation'] = $reputation;
            $score += $reputation['risk_score'];
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

    protected function isValidHostname(string $domain): bool
    {
        // RFC 1035 compliance check
        if (strlen($domain) > 253) {
            return false;
        }

        // Check each label
        $labels = explode('.', $domain);
        if (count($labels) < 2) {
            return false; // Must have at least 2 labels (domain.tld)
        }

        foreach ($labels as $label) {
            if (! preg_match('/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i', $label)) {
                return false;
            }
        }

        // Check TLD
        $tld = end($labels);
        if (! preg_match('/^[a-z]{2,}$/i', $tld)) {
            return false;
        }

        return true;
    }

    protected function checkMXRecords(string $domain): array
    {
        $cacheKey = "mx_records:{$domain}";

        return Cache::remember($cacheKey, 3600, function () use ($domain) {
            $mxRecords = [];
            $exists = getmxrr($domain, $mxRecords);

            return [
                'exists' => $exists,
                'count' => count($mxRecords),
                'records' => $exists ? array_slice($mxRecords, 0, 5) : [],
            ];
        });
    }

    protected function checkDomainAge(string $domain): ?array
    {
        try {
            // Check WHOIS data (this is a simplified version)
            // In production, you'd use a WHOIS API service
            $cacheKey = "domain_age:{$domain}";

            return Cache::remember($cacheKey, 86400, function () {
                // For now, return null as WHOIS lookup requires external service
                // You would integrate with services like:
                // - WhoisXML API
                // - DomainTools API
                // - WHOIS lookup libraries
                return null;
            });
        } catch (\Exception $e) {
            return null;
        }
    }

    protected function isParkedDomain(string $domain): bool
    {
        try {
            $response = Http::timeout(5)
                ->withHeaders(['User-Agent' => 'FraudDetector/1.0'])
                ->get("http://{$domain}");

            if (! $response->successful()) {
                return false;
            }

            $html = strtolower($response->body());

            // Common parked domain indicators
            $parkedIndicators = [
                'domain is for sale',
                'this domain is parked',
                'buy this domain',
                'domain parking',
                'under construction',
                'coming soon',
                'godaddy.com/domains',
                'sedo.com',
                'namecheap.com/domains',
            ];

            foreach ($parkedIndicators as $indicator) {
                if (str_contains($html, $indicator)) {
                    return true;
                }
            }

            return false;
        } catch (\Exception $e) {
            return false;
        }
    }

    protected function checkDNSConfiguration(string $domain): array
    {
        $riskScore = 0;
        $details = [];

        // Get DNS records
        $dnsRecords = dns_get_record($domain, DNS_ALL);

        if (empty($dnsRecords)) {
            return [
                'configured' => false,
                'risk_score' => 50,
            ];
        }

        $recordTypes = [];
        foreach ($dnsRecords as $record) {
            $recordTypes[] = $record['type'];
        }

        $details['record_types'] = array_unique($recordTypes);

        // Check for basic records
        if (! in_array('A', $recordTypes) && ! in_array('AAAA', $recordTypes)) {
            $riskScore += 20; // No A records
        }

        // Check for SPF record
        $hasSPF = false;
        foreach ($dnsRecords as $record) {
            if ($record['type'] === 'TXT' && str_contains($record['txt'] ?? '', 'v=spf1')) {
                $hasSPF = true;
                break;
            }
        }

        if (! $hasSPF) {
            $riskScore += 10; // No SPF record
        }

        $details['has_spf'] = $hasSPF;
        $details['risk_score'] = $riskScore;

        return $details;
    }

    protected function checkDomainReputation(string $domain): ?array
    {
        // Check if domain has been used in previous fraud attempts
        $previousChecks = FraudCheck::where('domain', $domain)
            ->where('created_at', '>=', now()->subMonths(6))
            ->select('risk_score', 'decision')
            ->get();

        if ($previousChecks->isEmpty()) {
            return null;
        }

        $avgRiskScore = $previousChecks->avg('risk_score');
        $blockCount = $previousChecks->where('decision', 'block')->count();

        $riskScore = 0;
        if ($avgRiskScore > 70) {
            $riskScore += 30;
        }
        if ($blockCount > 5) {
            $riskScore += 40;
        }

        return [
            'previous_checks' => $previousChecks->count(),
            'avg_risk_score' => round($avgRiskScore, 2),
            'block_count' => $blockCount,
            'risk_score' => $riskScore,
        ];
    }
}
