<?php

namespace App\Services\FraudDetection\DataSources;

use App\Models\DisposableEmailDomain;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;

class DisposableEmailUpdater
{
    protected array $sources = [
        'disposable-email-domains' => [
            'url' => 'https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf',
            'format' => 'text',
        ],
        'mailchecker' => [
            'url' => 'https://raw.githubusercontent.com/FGRibreau/mailchecker/master/list.txt',
            'format' => 'text',
        ],
        'burner-email-providers' => [
            'url' => 'https://raw.githubusercontent.com/wesbos/burner-email-providers/master/emails.txt',
            'format' => 'text',
        ],
        'disposable-email-domains-json' => [
            'url' => 'https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/index.json',
            'format' => 'json',
        ],
        'temp-mail-domains' => [
            'url' => 'https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/wildcard.json',
            'format' => 'json',
        ],
    ];

    /**
     * Update disposable email domains from all sources.
     */
    public function updateAll(): array
    {
        $results = [];
        $allDomains = [];

        foreach ($this->sources as $name => $config) {
            try {
                $domains = $this->fetchFromSource($name, $config);
                $results[$name] = [
                    'success' => true,
                    'count' => count($domains),
                ];
                $allDomains = array_merge($allDomains, $domains);
            } catch (\Exception $e) {
                $results[$name] = [
                    'success' => false,
                    'error' => $e->getMessage(),
                ];
                Log::error("Failed to fetch disposable domains from {$name}", [
                    'error' => $e->getMessage(),
                ]);
            }
        }

        // Also check for local custom list
        $customDomains = $this->loadCustomDomains();
        if (! empty($customDomains)) {
            $allDomains = array_merge($allDomains, $customDomains);
            $results['custom'] = [
                'success' => true,
                'count' => count($customDomains),
            ];
        }

        // Remove duplicates and clean
        $uniqueDomains = $this->cleanAndDeduplicateDomains($allDomains);

        // Validate domains
        $validDomains = $this->validateDomains($uniqueDomains);

        // Update database
        $this->updateDatabase($validDomains);

        // Save combined list for reference
        $this->saveCombinedList($validDomains);

        return [
            'sources' => $results,
            'total_domains' => count($validDomains),
            'duplicates_removed' => count($uniqueDomains) - count($validDomains),
        ];
    }

    /**
     * Fetch domains from a specific source.
     */
    protected function fetchFromSource(string $name, array $config): array
    {
        $response = Http::timeout(30)->get($config['url']);

        if (! $response->successful()) {
            throw new \Exception('HTTP request failed with status: '.$response->status());
        }

        switch ($config['format']) {
            case 'text':
                return $this->parseTextFormat($response->body());
            case 'json':
                return $this->parseJsonFormat($response->json());
            default:
                return [];
        }
    }

    /**
     * Parse text format (one domain per line).
     */
    protected function parseTextFormat(string $content): array
    {
        $domains = [];
        $lines = explode("\n", $content);

        foreach ($lines as $line) {
            $domain = trim($line);

            // Skip comments and empty lines
            if (empty($domain) || str_starts_with($domain, '#') || str_starts_with($domain, '//')) {
                continue;
            }

            // Remove any inline comments
            if (($pos = strpos($domain, '#')) !== false) {
                $domain = trim(substr($domain, 0, $pos));
            }

            if (! empty($domain)) {
                $domains[] = strtolower($domain);
            }
        }

        return $domains;
    }

    /**
     * Parse JSON format.
     */
    protected function parseJsonFormat($data): array
    {
        if (! is_array($data)) {
            return [];
        }

        return array_map('strtolower', $data);
    }

    /**
     * Load custom domains from local file.
     */
    protected function loadCustomDomains(): array
    {
        $path = 'fraud-detection/custom-disposable-domains.txt';

        if (! Storage::exists($path)) {
            return [];
        }

        $content = Storage::get($path);

        return $this->parseTextFormat($content);
    }

    /**
     * Clean and deduplicate domains.
     */
    protected function cleanAndDeduplicateDomains(array $domains): array
    {
        $cleaned = [];

        foreach ($domains as $domain) {
            // Basic cleaning
            $domain = trim(strtolower($domain));

            // Remove wildcards (we'll handle subdomains differently)
            $domain = ltrim($domain, '*.');

            // Skip invalid entries
            if (empty($domain) || strlen($domain) < 4) {
                continue;
            }

            $cleaned[] = $domain;
        }

        return array_unique($cleaned);
    }

    /**
     * Validate domain format.
     */
    protected function validateDomains(array $domains): array
    {
        $valid = [];

        foreach ($domains as $domain) {
            if ($this->isValidDomain($domain)) {
                $valid[] = $domain;
            } else {
                Log::debug("Invalid domain format: {$domain}");
            }
        }

        return $valid;
    }

    /**
     * Check if domain format is valid.
     */
    protected function isValidDomain(string $domain): bool
    {
        // Basic domain validation
        if (! preg_match('/^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i', $domain)) {
            return false;
        }

        // Check for common issues
        if (str_contains($domain, '..') || str_starts_with($domain, '.') || str_ends_with($domain, '.')) {
            return false;
        }

        // Validate TLD
        $parts = explode('.', $domain);
        $tld = end($parts);
        if (strlen($tld) < 2 || ! ctype_alpha($tld)) {
            return false;
        }

        return true;
    }

    /**
     * Update database with validated domains.
     */
    protected function updateDatabase(array $domains): void
    {
        DB::transaction(function () use ($domains) {
            // Mark all existing domains as inactive
            DisposableEmailDomain::query()->update(['is_active' => false]);

            // Batch upsert domains
            $chunks = array_chunk($domains, 1000);

            foreach ($chunks as $chunk) {
                $data = [];

                foreach ($chunk as $domain) {
                    $data[] = [
                        'domain' => $domain,
                        'source' => 'automated',
                        'risk_weight' => $this->calculateRiskWeight($domain),
                        'is_active' => true,
                        'verified_at' => now(),
                        'created_at' => now(),
                        'updated_at' => now(),
                    ];
                }

                DisposableEmailDomain::upsert(
                    $data,
                    ['domain'], // Unique key
                    ['source', 'is_active', 'verified_at', 'updated_at']
                );
            }

            // Remove domains not seen in multiple updates
            DisposableEmailDomain::where('is_active', false)
                ->where('updated_at', '<', now()->subDays(7))
                ->delete();
        });
    }

    /**
     * Calculate risk weight for domain.
     */
    protected function calculateRiskWeight(string $domain): int
    {
        // Known high-risk patterns
        $highRiskPatterns = [
            'temp' => 90,
            'trash' => 90,
            'throwaway' => 90,
            'disposable' => 90,
            'guerrilla' => 85,
            'mailinator' => 85,
            '10minute' => 85,
            'yopmail' => 85,
        ];

        foreach ($highRiskPatterns as $pattern => $weight) {
            if (str_contains($domain, $pattern)) {
                return $weight;
            }
        }

        // Default weight for disposable domains
        return 80;
    }

    /**
     * Save combined list for reference.
     */
    protected function saveCombinedList(array $domains): void
    {
        $content = "# Disposable Email Domains\n";
        $content .= '# Generated: '.now()->toDateTimeString()."\n";
        $content .= '# Total domains: '.count($domains)."\n\n";

        sort($domains);
        $content .= implode("\n", $domains);

        Storage::put('fraud-detection/disposable-domains-combined.txt', $content);
    }
}
