<?php

namespace App\Services\FraudDetection\DataSources;

use App\Models\KnownUserAgent;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class UserAgentUpdater
{
    protected array $sources = [
        'known_bots' => [
            'url' => 'https://raw.githubusercontent.com/monperrus/crawler-user-agents/master/crawler-user-agents.json',
            'format' => 'json',
            'type' => 'bot',
        ],
        // Simplified sources to avoid memory issues
    ];

    protected array $maliciousPatterns = [
        'sqlmap' => 95,
        'nikto' => 90,
        'nmap' => 85,
        'masscan' => 85,
        'metasploit' => 95,
        'burpsuite' => 85,
        'burp' => 85,
        'dirb' => 80,
        'gobuster' => 80,
        'dirbuster' => 80,
        'wfuzz' => 85,
        'hydra' => 90,
        'havij' => 90,
        'acunetix' => 85,
        'nessus' => 80,
        'openvas' => 80,
        'w3af' => 80,
        'skipfish' => 75,
        'arachni' => 80,
        'zap' => 75, // OWASP ZAP
        'zaproxy' => 75,
        'nuclei' => 85,
        'commix' => 85,
        'xsser' => 85,
        'beef' => 90, // Browser Exploitation Framework
    ];

    protected array $botPatterns = [
        // Search engines
        'googlebot' => 40,
        'bingbot' => 40,
        'slurp' => 40, // Yahoo
        'duckduckbot' => 40,
        'baiduspider' => 45,
        'yandexbot' => 45,

        // Social media
        'facebookexternalhit' => 30,
        'twitterbot' => 30,
        'linkedinbot' => 30,
        'whatsapp' => 25,
        'telegrambot' => 50,

        // Tools
        'curl' => 70,
        'wget' => 70,
        'python-requests' => 70,
        'python-urllib' => 70,
        'postman' => 60,
        'insomnia' => 60,
        'httpie' => 65,
        'node-fetch' => 65,
        'axios' => 65,

        // Scrapers
        'scrapy' => 75,
        'beautifulsoup' => 75,
        'selenium' => 80,
        'phantomjs' => 80,
        'headlesschrome' => 70,
        'puppeteer' => 70,
        'playwright' => 70,
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
     * Update known user agents from all sources.
     */
    public function updateAll(): array
    {
        ini_set('memory_limit', '256M');

        $results = [];
        $totalUserAgents = 0;

        Log::info('Starting User Agent database update', [
            'memory_limit' => ini_get('memory_limit'),
            'initial_memory' => memory_get_usage(true),
        ]);

        // Process external sources
        foreach ($this->sources as $name => $config) {
            try {
                $count = $this->fetchAndProcessSource($name, $config);
                $results[$name] = [
                    'success' => true,
                    'count' => $count,
                ];
                $totalUserAgents += $count;

                gc_collect_cycles();

            } catch (\Exception $e) {
                $results[$name] = [
                    'success' => false,
                    'error' => $e->getMessage(),
                ];
                Log::error("Failed to fetch user agents from {$name}", [
                    'error' => $e->getMessage(),
                ]);
            }
        }

        // Add known patterns
        try {
            $count = $this->generateKnownPatterns();
            $results['known_patterns'] = [
                'success' => true,
                'count' => $count,
            ];
            $totalUserAgents += $count;
        } catch (\Exception $e) {
            $results['known_patterns'] = [
                'success' => false,
                'error' => $e->getMessage(),
            ];
        }

        Log::info('User Agent database update completed', [
            'total_user_agents' => $totalUserAgents,
            'peak_memory' => memory_get_peak_usage(true),
        ]);

        return [
            'sources' => $results,
            'total_user_agents' => $totalUserAgents,
        ];
    }

    /**
     * Fetch and process user agents from a source.
     */
    protected function fetchAndProcessSource(string $name, array $config): int
    {
        $response = Http::timeout(30)->get($config['url']);

        if (!$response->successful()) {
            throw new \Exception('HTTP request failed with status: ' . $response->status());
        }

        $processedCount = 0;

        switch ($config['format']) {
            case 'json':
                $processedCount = $this->processJsonSource($response->json(), $config);
                break;
            case 'text':
                $processedCount = $this->processTextSource($response->body(), $config);
                break;
        }

        return $processedCount;
    }

    /**
     * Process JSON format user agent data.
     */
    protected function processJsonSource(array $data, array $config): int
    {
        if (empty($data)) {
            return 0;
        }

        $batch = [];
        $processedCount = 0;

        foreach ($data as $entry) {
            $userAgent = null;
            $name = null;

            // Handle different JSON structures
            if (isset($entry['pattern'])) {
                $userAgent = $entry['pattern'];
                $name = $entry['name'] ?? 'Unknown Bot';
            } elseif (isset($entry['userAgent'])) {
                $userAgent = $entry['userAgent'];
                $name = $entry['browser'] ?? $entry['name'] ?? 'Unknown';
            } elseif (is_string($entry)) {
                $userAgent = $entry;
                $name = 'Unknown';
            }

            if ($userAgent && strlen($userAgent) > 10) { // Basic validation
                $batch[] = [
                    'user_agent' => $userAgent,
                    'type' => $config['type'] ?? 'bot',
                    'name' => $name,
                    'version' => $entry['version'] ?? null,
                    'source' => 'external',
                ];

                if (count($batch) >= $this->batchSize) {
                    $this->processUserAgentBatch($batch);
                    $processedCount += count($batch);
                    $batch = [];

                    // Memory management
                    if ($processedCount % 2000 === 0) {
                        gc_collect_cycles();
                    }
                }
            }
        }

        // Process remaining user agents
        if (!empty($batch)) {
            $this->processUserAgentBatch($batch);
            $processedCount += count($batch);
        }

        return $processedCount;
    }

    /**
     * Process text format user agent data.
     */
    protected function processTextSource(string $content, array $config): int
    {
        $lines = explode("\n", $content);
        $batch = [];
        $processedCount = 0;

        foreach ($lines as $line) {
            $userAgent = trim($line);

            if (!empty($userAgent) && !str_starts_with($userAgent, '#') && strlen($userAgent) > 10) {
                $batch[] = [
                    'user_agent' => $userAgent,
                    'type' => $config['type'] ?? 'unknown',
                    'name' => 'Unknown',
                    'source' => 'external',
                ];

                if (count($batch) >= $this->batchSize) {
                    $this->processUserAgentBatch($batch);
                    $processedCount += count($batch);
                    $batch = [];
                }
            }
        }

        // Process remaining user agents
        if (!empty($batch)) {
            $this->processUserAgentBatch($batch);
            $processedCount += count($batch);
        }

        return $processedCount;
    }

    /**
     * Generate known malicious and bot patterns.
     */
    protected function generateKnownPatterns(): int
    {
        $patterns = [];

        // Add malicious patterns
        foreach ($this->maliciousPatterns as $pattern => $riskWeight) {
            $patterns[] = [
                'user_agent' => $pattern,
                'type' => 'malicious',
                'name' => ucfirst($pattern),
                'risk_weight' => $riskWeight,
                'source' => 'internal',
            ];
        }

        // Add bot patterns
        foreach ($this->botPatterns as $pattern => $riskWeight) {
            $patterns[] = [
                'user_agent' => $pattern,
                'type' => 'bot',
                'name' => ucfirst($pattern),
                'risk_weight' => $riskWeight,
                'source' => 'internal',
            ];
        }

        // Add common outdated browsers
        $outdatedBrowsers = [
            'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)' => ['Internet Explorer', '6.0', 90, '2014-04-08'],
            'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)' => ['Internet Explorer', '7.0', 80, '2014-04-08'],
            'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)' => ['Internet Explorer', '8.0', 70, '2016-01-12'],
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1)' => ['Internet Explorer', '9.0', 60, '2016-01-12'],
            'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2)' => ['Internet Explorer', '10.0', 50, '2020-01-14'],
        ];

        foreach ($outdatedBrowsers as $ua => $info) {
            $patterns[] = [
                'user_agent' => $ua,
                'type' => 'browser',
                'name' => $info[0],
                'version' => $info[1],
                'risk_weight' => $info[2],
                'is_outdated' => true,
                'eol_date' => $info[3],
                'source' => 'internal',
            ];
        }

        // Process in batches
        $processedCount = 0;
        $chunks = array_chunk($patterns, $this->batchSize);

        foreach ($chunks as $chunk) {
            $this->processUserAgentBatch($chunk);
            $processedCount += count($chunk);
        }

        return $processedCount;
    }

    /**
     * Process a batch of user agents.
     */
    protected function processUserAgentBatch(array $userAgents): void
    {
        if (empty($userAgents)) {
            return;
        }

        $data = [];
        $now = now();

        foreach ($userAgents as $ua) {
            $userAgentString = $ua['user_agent'];
            $hash = hash('sha256', $userAgentString);

            // Classify if not already classified
            if (!isset($ua['risk_weight'])) {
                $ua['risk_weight'] = $this->calculateRiskWeight($ua);
            }

            // Extract version if not set
            if (!isset($ua['version']) && $ua['type'] === 'browser') {
                $ua['version'] = $this->extractVersion($userAgentString);
            }

            // Check if outdated
            if (!isset($ua['is_outdated'])) {
                $ua['is_outdated'] = $this->isOutdated($ua);
            }

            $data[] = [
                'user_agent' => substr($userAgentString, 0, 1000), // Limit length
                'user_agent_hash' => $hash,
                'type' => $ua['type'],
                'name' => substr($ua['name'] ?? 'Unknown', 0, 255),
                'version' => $ua['version'] ?? null,
                'risk_weight' => $ua['risk_weight'],
                'is_outdated' => $ua['is_outdated'] ?? false,
                'eol_date' => $ua['eol_date'] ?? null,
                'created_at' => $now,
                'updated_at' => $now,
            ];
        }

        // Upsert user agents
        KnownUserAgent::upsert(
            $data,
            ['user_agent_hash'], // Unique key
            ['type', 'name', 'version', 'risk_weight', 'is_outdated', 'eol_date', 'updated_at']
        );

        // Clear data array from memory
        unset($data);
    }

    /**
     * Calculate risk weight for user agent.
     */
    protected function calculateRiskWeight(array $ua): int
    {
        $weight = 0;

        switch ($ua['type']) {
            case 'malicious':
                $weight = 95;
                break;
            case 'bot':
                $weight = 60;
                break;
            case 'browser':
                $weight = 0;
                break;
            default:
                $weight = 30;
        }

        // Increase weight for outdated software
        if ($ua['is_outdated'] ?? false) {
            $weight += 30;
        }

        return min($weight, 100);
    }

    /**
     * Extract version from user agent string.
     */
    protected function extractVersion(string $userAgent): ?string
    {
        $patterns = [
            '/Chrome\/(\d+(?:\.\d+)?)/',
            '/Firefox\/(\d+(?:\.\d+)?)/',
            '/Safari\/(\d+(?:\.\d+)?)/',
            '/MSIE (\d+(?:\.\d+)?)/',
            '/Edge\/(\d+(?:\.\d+)?)/',
            '/Version\/(\d+(?:\.\d+)?)/',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $userAgent, $matches)) {
                return $matches[1];
            }
        }

        return null;
    }

    /**
     * Check if user agent represents outdated software.
     */
    protected function isOutdated(array $ua): bool
    {
        $userAgent = strtolower($ua['user_agent']);

        // Known outdated patterns
        $outdatedPatterns = [
            'msie 6', 'msie 7', 'msie 8', 'msie 9', 'msie 10',
            'chrome/1', 'chrome/2', 'chrome/3', 'chrome/4',
            'firefox/1', 'firefox/2', 'firefox/3', 'firefox/4',
        ];

        foreach ($outdatedPatterns as $pattern) {
            if (str_contains($userAgent, $pattern)) {
                return true;
            }
        }

        return false;
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
