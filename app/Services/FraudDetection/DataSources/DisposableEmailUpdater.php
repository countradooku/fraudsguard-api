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
    ];

    protected int $chunkSize = 1000;

    protected int $memoryLimit;

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
     * Update disposable email domains from all sources.
     */
    public function updateAll(): array
    {
        // Increase memory limit
        ini_set('memory_limit', '512M');

        $results = [];
        $totalDomains = 0;

        // Mark all existing domains as inactive first
        DB::statement('UPDATE disposable_email_domains SET is_active = false');

        foreach ($this->sources as $name => $config) {
            try {
                $count = $this->fetchAndProcessSource($name, $config);
                $results[$name] = [
                    'success' => true,
                    'count' => $count,
                ];
                $totalDomains += $count;

                // Force garbage collection after each source
                gc_collect_cycles();

            } catch (\Exception $e) {
                $results[$name] = [
                    'success' => false,
                    'error' => $e->getMessage(),
                ];
                Log::error("Failed to fetch disposable domains from {$name}", [
                    'error' => $e->getMessage(),
                ]);
            }

            // Check memory usage
            if (memory_get_usage() > $this->memoryLimit) {
                Log::warning('Memory usage high, forcing garbage collection', [
                    'memory_usage' => memory_get_usage(true),
                    'memory_peak' => memory_get_peak_usage(true),
                ]);
                gc_collect_cycles();
            }
        }

        // Also check for local custom list
        try {
            $customCount = $this->loadAndProcessCustomDomains();
            if ($customCount > 0) {
                $totalDomains += $customCount;
                $results['custom'] = [
                    'success' => true,
                    'count' => $customCount,
                ];
            }
        } catch (\Exception $e) {
            $results['custom'] = [
                'success' => false,
                'error' => $e->getMessage(),
            ];
        }

        // Clean up old inactive domains
        $this->cleanupOldDomains();

        return [
            'sources' => $results,
            'total_domains' => $totalDomains,
        ];
    }

    /**
     * Fetch and process domains from a source using streaming.
     */
    protected function fetchAndProcessSource(string $name, array $config): int
    {
        $tempFile = tempnam(sys_get_temp_dir(), "disposable_emails_{$name}_");
        $processedCount = 0;

        try {
            // Download to temporary file to avoid keeping large response in memory
            $response = Http::timeout(30)->sink($tempFile)->get($config['url']);

            if (! $response->successful()) {
                throw new \Exception('HTTP request failed with status: '.$response->status());
            }

            // Process file line by line
            $handle = fopen($tempFile, 'r');
            if (! $handle) {
                throw new \Exception('Could not open temporary file');
            }

            $batch = [];
            $batchSize = 500; // Smaller batch size for memory efficiency

            while (($line = fgets($handle)) !== false) {
                $domain = $this->cleanDomain(trim($line));

                if ($this->isValidDomain($domain)) {
                    $batch[] = $domain;

                    if (count($batch) >= $batchSize) {
                        $this->processBatch($batch);
                        $processedCount += count($batch);
                        $batch = []; // Clear batch from memory

                        // Periodic garbage collection
                        if ($processedCount % 5000 === 0) {
                            gc_collect_cycles();
                        }
                    }
                }
            }

            // Process remaining domains
            if (! empty($batch)) {
                $this->processBatch($batch);
                $processedCount += count($batch);
            }

            fclose($handle);

        } finally {
            @unlink($tempFile);
        }

        return $processedCount;
    }

    /**
     * Process a batch of domains.
     */
    protected function processBatch(array $domains): void
    {
        if (empty($domains)) {
            return;
        }

        $data = [];
        $now = now();

        foreach ($domains as $domain) {
            $data[] = [
                'domain' => $domain,
                'source' => 'automated',
                'risk_weight' => $this->calculateRiskWeight($domain),
                'is_active' => true,
                'verified_at' => $now,
                'created_at' => $now,
                'updated_at' => $now,
            ];
        }

        // Use upsert to handle duplicates efficiently
        DisposableEmailDomain::upsert(
            $data,
            ['domain'], // Unique key
            ['source', 'is_active', 'verified_at', 'updated_at']
        );

        // Clear data array from memory
        unset($data);
    }

    /**
     * Clean domain string.
     */
    protected function cleanDomain(string $line): string
    {
        // Skip comments and empty lines
        if (empty($line) || str_starts_with($line, '#') || str_starts_with($line, '//')) {
            return '';
        }

        // Remove any inline comments
        if (($pos = strpos($line, '#')) !== false) {
            $line = trim(substr($line, 0, $pos));
        }

        // Remove wildcards
        $domain = ltrim($line, '*.');

        return strtolower($domain);
    }

    /**
     * Validate domain format.
     */
    protected function isValidDomain(string $domain): bool
    {
        if (empty($domain) || strlen($domain) < 4) {
            return false;
        }

        // Basic domain validation
        if (! preg_match('/^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i', $domain)) {
            return false;
        }

        // Check for common issues
        if (str_contains($domain, '..') || str_starts_with($domain, '.') || str_ends_with($domain, '.')) {
            return false;
        }

        return true;
    }

    /**
     * Load and process custom domains.
     */
    protected function loadAndProcessCustomDomains(): int
    {
        $path = 'fraud-detection/custom-disposable-domains.txt';

        if (! Storage::exists($path)) {
            return 0;
        }

        $tempFile = tempnam(sys_get_temp_dir(), 'custom_domains_');
        Storage::copy($path, $tempFile);

        $processedCount = 0;

        try {
            $handle = fopen($tempFile, 'r');
            if (! $handle) {
                return 0;
            }

            $batch = [];
            $batchSize = 500;

            while (($line = fgets($handle)) !== false) {
                $domain = $this->cleanDomain(trim($line));

                if ($this->isValidDomain($domain)) {
                    $batch[] = $domain;

                    if (count($batch) >= $batchSize) {
                        $this->processBatch($batch);
                        $processedCount += count($batch);
                        $batch = [];
                    }
                }
            }

            // Process remaining domains
            if (! empty($batch)) {
                $this->processBatch($batch);
                $processedCount += count($batch);
            }

            fclose($handle);

        } finally {
            @unlink($tempFile);
        }

        return $processedCount;
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

        return 80; // Default weight
    }

    /**
     * Clean up old inactive domains.
     */
    protected function cleanupOldDomains(): void
    {
        DB::statement('DELETE FROM disposable_email_domains WHERE is_active = false AND updated_at < ?', [
            now()->subDays(7),
        ]);
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
