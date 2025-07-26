<?php

namespace App\Services\FraudDetection\Checks;

use App\Models\KnownUserAgent;
use Illuminate\Support\Facades\Cache;

class UserAgentCheck implements CheckInterface
{
    protected array $suspiciousPatterns = [
        'bot' => ['bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python'],
        'automation' => ['selenium', 'phantomjs', 'headless', 'automation', 'test'],
        'malicious' => ['nikto', 'sqlmap', 'nmap', 'metasploit', 'burp'],
    ];

    protected array $outdatedBrowsers = [
        'MSIE 6' => 90,
        'MSIE 7' => 80,
        'MSIE 8' => 70,
        'MSIE 9' => 60,
        'Chrome/1' => 80,
        'Chrome/2' => 70,
        'Firefox/1' => 80,
        'Firefox/2' => 70,
        'Firefox/3' => 60,
    ];

    public function applicable(array $data): bool
    {
        return !empty($data['user_agent']);
    }

    public function perform(array $data): array
    {
        $userAgent = trim($data['user_agent']);
        $details = [];
        $score = 0;
        $passed = true;

        // 1. Basic validation
        if (empty($userAgent) || strlen($userAgent) < 10) {
            return [
                'passed' => false,
                'score' => 50,
                'details' => ['error' => 'Invalid or suspiciously short user agent'],
            ];
        }

        $details['length'] = strlen($userAgent);
        $details['user_agent'] = substr($userAgent, 0, 100); // Truncate for storage

        // 2. Check against known user agents database
        $knownAgent = $this->checkKnownUserAgent($userAgent);
        if ($knownAgent) {
            $details['known_agent'] = $knownAgent;
            $score += $knownAgent['risk_score'];

            if ($knownAgent['type'] === 'malicious') {
                $passed = false;
            }
        }

        // 3. Pattern analysis
        $patternAnalysis = $this->analyzePatterns($userAgent);
        $details['patterns'] = $patternAnalysis;
        $score += $patternAnalysis['risk_score'];

        // 4. Browser analysis
        $browserInfo = $this->analyzeBrowser($userAgent);
        $details['browser'] = $browserInfo;
        $score += $browserInfo['risk_score'];

        // 5. Check for suspicious characteristics
        $suspiciousChecks = $this->checkSuspiciousCharacteristics($userAgent);
        $details['suspicious'] = $suspiciousChecks;
        $score += $suspiciousChecks['risk_score'];

        // 6. Frequency analysis
        $frequencyCheck = $this->checkFrequency($userAgent);
        if ($frequencyCheck) {
            $details['frequency'] = $frequencyCheck;
            $score += $frequencyCheck['risk_score'];
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

    protected function checkKnownUserAgent(string $userAgent): ?array
    {
        $hash = hash('sha256', $userAgent);

        return Cache::remember("known_ua:{$hash}", 3600, function () use ($userAgent, $hash) {
            // Check exact match first
            $knownAgent = KnownUserAgent::where('user_agent_hash', $hash)->first();

            if ($knownAgent) {
                return [
                    'type' => $knownAgent->type,
                    'name' => $knownAgent->name,
                    'version' => $knownAgent->version,
                    'risk_score' => $knownAgent->risk_weight,
                    'is_outdated' => $knownAgent->is_outdated,
                ];
            }

            // Check partial matches for known patterns
            foreach ($this->suspiciousPatterns as $type => $patterns) {
                foreach ($patterns as $pattern) {
                    if (str_contains(strtolower($userAgent), $pattern)) {
                        $riskScore = match($type) {
                            'malicious' => 90,
                            'bot' => 60,
                            'automation' => 70,
                            default => 30,
                        };

                        return [
                            'type' => $type,
                            'matched_pattern' => $pattern,
                            'risk_score' => $riskScore,
                        ];
                    }
                }
            }

            return null;
        });
    }

    protected function analyzePatterns(string $userAgent): array
    {
        $riskScore = 0;
        $flags = [];

        $userAgentLower = strtolower($userAgent);

        // Check for bot indicators
        if ($this->containsAny($userAgentLower, $this->suspiciousPatterns['bot'])) {
            $flags[] = 'bot_pattern';
            $riskScore += 40;
        }

        // Check for automation tools
        if ($this->containsAny($userAgentLower, $this->suspiciousPatterns['automation'])) {
            $flags[] = 'automation_pattern';
            $riskScore += 50;
        }

        // Check for malicious tools
        if ($this->containsAny($userAgentLower, $this->suspiciousPatterns['malicious'])) {
            $flags[] = 'malicious_pattern';
            $riskScore += 80;
        }

        // Check for programming languages/libraries
        $programmingPatterns = ['python', 'java', 'perl', 'ruby', 'node', 'go-http'];
        if ($this->containsAny($userAgentLower, $programmingPatterns)) {
            $flags[] = 'programming_language';
            $riskScore += 30;
        }

        return [
            'flags' => $flags,
            'risk_score' => $riskScore,
        ];
    }

    protected function analyzeBrowser(string $userAgent): array
    {
        $riskScore = 0;
        $browserInfo = [];

        // Parse browser information
        if (preg_match('/Firefox\/(\d+(?:\.\d+)?)/', $userAgent, $matches)) {
            $browserInfo['name'] = 'Firefox';
            $browserInfo['version'] = $matches[1];
        } elseif (preg_match('/Chrome\/(\d+(?:\.\d+)?)/', $userAgent, $matches)) {
            $browserInfo['name'] = 'Chrome';
            $browserInfo['version'] = $matches[1];
        } elseif (preg_match('/Safari\/(\d+(?:\.\d+)?)/', $userAgent, $matches)) {
            $browserInfo['name'] = 'Safari';
            $browserInfo['version'] = $matches[1];
        } elseif (preg_match('/MSIE (\d+(?:\.\d+)?)/', $userAgent, $matches)) {
            $browserInfo['name'] = 'Internet Explorer';
            $browserInfo['version'] = $matches[1];
            $riskScore += 30; // IE is generally higher risk
        }

        // Check for outdated browsers
        foreach ($this->outdatedBrowsers as $pattern => $risk) {
            if (str_contains($userAgent, $pattern)) {
                $browserInfo['outdated'] = true;
                $riskScore += $risk;
                break;
            }
        }

        // Check for mobile vs desktop consistency
        $isMobile = str_contains(strtolower($userAgent), 'mobile');
        $browserInfo['is_mobile'] = $isMobile;

        $browserInfo['risk_score'] = $riskScore;
        return $browserInfo;
    }

    protected function checkSuspiciousCharacteristics(string $userAgent): array
    {
        $riskScore = 0;
        $characteristics = [];

        // Very short user agent
        if (strlen($userAgent) < 20) {
            $characteristics[] = 'too_short';
            $riskScore += 30;
        }

        // Very long user agent
        if (strlen($userAgent) > 500) {
            $characteristics[] = 'too_long';
            $riskScore += 20;
        }

        // Missing common browser indicators
        $hasCommonIndicators = str_contains(strtolower($userAgent), 'mozilla') ||
            str_contains(strtolower($userAgent), 'webkit') ||
            str_contains(strtolower($userAgent), 'gecko');

        if (!$hasCommonIndicators) {
            $characteristics[] = 'missing_common_indicators';
            $riskScore += 25;
        }

        // Contains suspicious strings
        $suspiciousStrings = ['hack', 'exploit', 'inject', 'bypass', 'penetration'];
        foreach ($suspiciousStrings as $suspicious) {
            if (str_contains(strtolower($userAgent), $suspicious)) {
                $characteristics[] = 'contains_suspicious_string';
                $riskScore += 60;
                break;
            }
        }

        // Repeated characters (might indicate generated UA)
        if (preg_match('/(.)\1{10,}/', $userAgent)) {
            $characteristics[] = 'repeated_characters';
            $riskScore += 40;
        }

        // Invalid format
        if (!preg_match('/^[a-zA-Z0-9\s\(\)\[\]\/\.,;:_\-\+]+$/', $userAgent)) {
            $characteristics[] = 'invalid_characters';
            $riskScore += 50;
        }

        return [
            'characteristics' => $characteristics,
            'risk_score' => $riskScore,
        ];
    }

    protected function checkFrequency(string $userAgent): ?array
    {
        $hash = hash('sha256', $userAgent);
        $key = "ua_frequency:{$hash}";

        $count = Cache::get($key, 0);
        Cache::put($key, $count + 1, now()->addDay());

        if ($count === 0) {
            return null; // First time seeing this UA
        }

        $riskScore = 0;
        $details = ['frequency' => $count + 1];

        // Very high frequency might indicate bot activity
        if ($count > 1000) {
            $riskScore += 20;
            $details['high_frequency'] = true;
        } elseif ($count > 100) {
            $riskScore += 10;
        }

        $details['risk_score'] = $riskScore;
        return $details;
    }

    protected function containsAny(string $haystack, array $needles): bool
    {
        foreach ($needles as $needle) {
            if (str_contains($haystack, $needle)) {
                return true;
            }
        }
        return false;
    }
}
