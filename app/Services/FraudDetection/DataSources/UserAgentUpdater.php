<?php

namespace App\Services\FraudDetection\DataSources;

use App\Models\KnownUserAgent;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class UserAgentUpdater
{
    protected array $sources = [
        'bot_detection' => [
            'url' => 'https://raw.githubusercontent.com/monperrus/crawler-user-agents/master/crawler-user-agents.json',
            'format' => 'json',
        ],
        'browser_detection' => [
            'url' => 'https://raw.githubusercontent.com/browscap/browscap/master/resources/user-agents/browsers.json',
            'format' => 'json',
        ],
    ];

    protected array $maliciousPatterns = [
        'sqlmap' => 90,
        'nikto' => 90,
        'nmap' => 85,
        'masscan' => 85,
        'metasploit' => 95,
        'burpsuite' => 80,
        'dirb' => 75,
        'gobuster' => 75,
        'wfuzz' => 80,
        'hydra' => 85,
        'havij' => 90,
        'acunetix' => 85,
        'nessus' => 80,
        'openvas' => 80,
        'w3af' => 80,
        'skipfish' => 75,
        'arachni' => 80,
        'zap' => 75, // OWASP ZAP
        'nuclei' => 85,
    ];

    protected array $botPatterns = [
        'googlebot' => 50,
        'bingbot' => 50,
        'slurp' => 50, // Yahoo
        'duckduckbot' => 50,
        'baiduspider' => 50,
        'yandexbot' => 50,
        'facebookexternalhit' => 40,
        'twitterbot' => 40,
        'linkedinbot' => 40,
        'whatsapp' => 30,
        'telegrambot' => 60,
        'curl' => 70,
        'wget' => 70,
        'python-requests' => 70,
        'postman' => 60,
        'insomnia' => 60,
        'httpie' => 65,
    ];

    /**
     * Update known user agents from all sources.
     */
    public function updateAll(): array
    {
        $results = [];
        $allUserAgents = [];

        foreach ($this->sources as $name => $config) {
            try {
                $userAgents = $this->fetchFromSource($name, $config);
                $results[$name] = [
                    'success' => true,
                    'count' => count($userAgents),
                ];
                $allUserAgents = array_merge($allUserAgents, $userAgents);
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

        // Add known malicious and bot patterns
        $allUserAgents = array_merge($allUserAgents, $this->generateKnownPatterns());

        // Classify and clean user agents
        $classifiedUserAgents = $this->classifyUserAgents($allUserAgents);

        // Update database
        $this->updateDatabase($classifiedUserAgents);

        return [
            'sources' => $results,
            'total_user_agents' => count($classifiedUserAgents),
        ];
    }

    /**
     * Fetch user agents from a specific source.
     */
    protected function fetchFromSource(string $name, array $config): array
    {
        $response = Http::timeout(30)->get($config['url']);

        if (! $response->successful()) {
            throw new \Exception('HTTP request failed with status: '.$response->status());
        }

        switch ($config['format']) {
            case 'json':
                return $this->parseJsonFormat($response->json(), $name);
            default:
                return [];
        }
    }

    /**
     * Parse JSON format user agent data.
     */
    protected function parseJsonFormat(array $data, string $source): array
    {
        $userAgents = [];

        switch ($source) {
            case 'bot_detection':
                foreach ($data as $entry) {
                    if (isset($entry['pattern'])) {
                        $userAgents[] = [
                            'user_agent' => $entry['pattern'],
                            'type' => 'bot',
                            'name' => $entry['name'] ?? 'Unknown Bot',
                            'source' => $source,
                        ];
                    }
                }
                break;

            case 'browser_detection':
                foreach ($data as $entry) {
                    if (isset($entry['userAgent'])) {
                        $userAgents[] = [
                            'user_agent' => $entry['userAgent'],
                            'type' => 'browser',
                            'name' => $entry['browser'] ?? 'Unknown Browser',
                            'version' => $entry['version'] ?? null,
                            'source' => $source,
                        ];
                    }
                }
                break;
        }

        return $userAgents;
    }

    /**
     * Generate known malicious and bot patterns.
     */
    protected function generateKnownPatterns(): array
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
            'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)' => ['Internet Explorer', '6.0', 90],
            'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)' => ['Internet Explorer', '7.0', 80],
            'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)' => ['Internet Explorer', '8.0', 70],
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1)' => ['Internet Explorer', '9.0', 60],
        ];

        foreach ($outdatedBrowsers as $ua => $info) {
            $patterns[] = [
                'user_agent' => $ua,
                'type' => 'browser',
                'name' => $info[0],
                'version' => $info[1],
                'risk_weight' => $info[2],
                'is_outdated' => true,
                'eol_date' => '2022-06-15', // IE EOL date
                'source' => 'internal',
            ];
        }

        return $patterns;
    }

    /**
     * Classify user agents and add metadata.
     */
    protected function classifyUserAgents(array $userAgents): array
    {
        $classified = [];

        foreach ($userAgents as $ua) {
            // Skip if no user agent string
            if (empty($ua['user_agent'])) {
                continue;
            }

            // Determine risk weight if not already set
            if (! isset($ua['risk_weight'])) {
                $ua['risk_weight'] = $this->calculateRiskWeight($ua);
            }

            // Parse version if not set
            if (! isset($ua['version']) && $ua['type'] === 'browser') {
                $ua['version'] = $this->extractVersion($ua['user_agent']);
            }

            // Check if outdated
            if (! isset($ua['is_outdated'])) {
                $ua['is_outdated'] = $this->isOutdated($ua);
            }

            // Set EOL date for known outdated software
            if ($ua['is_outdated'] && ! isset($ua['eol_date'])) {
                $ua['eol_date'] = $this->getEolDate($ua);
            }

            $classified[] = $ua;
        }

        return $classified;
    }

    /**
     * Calculate risk weight for user agent.
     */
    protected function calculateRiskWeight(array $ua): int
    {
        $weight = 0;

        switch ($ua['type']) {
            case 'malicious':
                $weight = 90;
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
        // Common version patterns
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
            'msie 6', 'msie 7', 'msie 8', 'msie 9',
            'chrome/1', 'chrome/2', 'chrome/3',
            'firefox/1', 'firefox/2', 'firefox/3',
        ];

        foreach ($outdatedPatterns as $pattern) {
            if (str_contains($userAgent, $pattern)) {
                return true;
            }
        }

        // Check version numbers for modern browsers
        if (isset($ua['version']) && is_numeric($ua['version'])) {
            $version = (float) $ua['version'];
            $name = strtolower($ua['name'] ?? '');

            if (str_contains($name, 'chrome') && $version < 100) {
                return true;
            }
            if (str_contains($name, 'firefox') && $version < 90) {
                return true;
            }
            if (str_contains($name, 'safari') && $version < 14) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get EOL date for known software.
     */
    protected function getEolDate(array $ua): ?string
    {
        $name = strtolower($ua['name'] ?? '');

        if (str_contains($name, 'internet explorer')) {
            return '2022-06-15'; // IE EOL
        }

        // Add more EOL dates as needed
        return null;
    }

    /**
     * Update database with classified user agents.
     */
    protected function updateDatabase(array $userAgents): void
    {
        DB::transaction(function () use ($userAgents) {
            // Process in chunks
            $chunks = array_chunk($userAgents, 500);

            foreach ($chunks as $chunk) {
                $data = [];

                foreach ($chunk as $ua) {
                    $userAgentString = $ua['user_agent'];
                    $hash = hash('sha256', $userAgentString);

                    $data[] = [
                        'user_agent' => $userAgentString,
                        'user_agent_hash' => $hash,
                        'type' => $ua['type'],
                        'name' => $ua['name'] ?? 'Unknown',
                        'version' => $ua['version'] ?? null,
                        'risk_weight' => $ua['risk_weight'],
                        'is_outdated' => $ua['is_outdated'] ?? false,
                        'eol_date' => isset($ua['eol_date']) ? $ua['eol_date'] : null,
                        'created_at' => now(),
                        'updated_at' => now(),
                    ];
                }

                // Upsert user agents
                KnownUserAgent::upsert(
                    $data,
                    ['user_agent_hash'], // Unique key
                    ['type', 'name', 'version', 'risk_weight', 'is_outdated', 'eol_date', 'updated_at']
                );
            }
        });
    }
}
