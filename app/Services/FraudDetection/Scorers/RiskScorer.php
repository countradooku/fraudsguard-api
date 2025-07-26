<?php

namespace App\Services\FraudDetection\Scorers;

use Illuminate\Support\Facades\Config;

class RiskScorer
{
    protected array $weights;

    protected array $thresholds;

    public function __construct()
    {
        $this->weights = [
            'email' => 0.25,
            'domain' => 0.15,
            'ip' => 0.25,
            'credit_card' => 0.20,
            'phone' => 0.10,
            'user_agent' => 0.05,
        ];

        $this->thresholds = Config::get('fraud-detection.risk_thresholds', [
            'low' => 30,
            'medium' => 50,
            'high' => 80,
            'critical' => 100,
        ]);
    }

    /**
     * Calculate overall risk score from individual check results
     */
    public function calculateScore(array $checkResults): int
    {
        $weightedSum = 0;
        $totalWeight = 0;

        foreach ($checkResults as $checkName => $result) {
            if (! isset($this->weights[$checkName])) {
                continue;
            }

            $score = $result['score'] ?? 0;
            $weight = $this->weights[$checkName];

            // Apply weight
            $weightedSum += $score * $weight;
            $totalWeight += $weight;
        }

        // Calculate weighted average
        if ($totalWeight > 0) {
            $averageScore = $weightedSum / $totalWeight;
        } else {
            $averageScore = 0;
        }

        // Apply modifiers
        $finalScore = $this->applyModifiers($averageScore, $checkResults);

        // Ensure score is within bounds
        return max(0, min(100, round($finalScore)));
    }

    /**
     * Apply scoring modifiers based on combinations and patterns
     */
    protected function applyModifiers(float $baseScore, array $checkResults): float
    {
        $modifiedScore = $baseScore;

        // Multiple high-risk indicators
        $highRiskCount = $this->countHighRiskIndicators($checkResults);
        if ($highRiskCount >= 3) {
            $modifiedScore *= 1.3; // 30% increase
        } elseif ($highRiskCount >= 2) {
            $modifiedScore *= 1.15; // 15% increase
        }

        // Critical failures
        if ($this->hasCriticalFailure($checkResults)) {
            $modifiedScore = max($modifiedScore, 90); // Minimum 90 score
        }

        // Pattern detection
        $patterns = $this->detectPatterns($checkResults);
        foreach ($patterns as $pattern => $modifier) {
            $modifiedScore *= $modifier;
        }

        // Velocity concerns across multiple checks
        if ($this->hasVelocityConcerns($checkResults)) {
            $modifiedScore *= 1.2; // 20% increase
        }

        return $modifiedScore;
    }

    /**
     * Count high-risk indicators
     */
    protected function countHighRiskIndicators(array $checkResults): int
    {
        $count = 0;

        foreach ($checkResults as $result) {
            if (($result['score'] ?? 0) >= $this->thresholds['high']) {
                $count++;
            }
        }

        return $count;
    }

    /**
     * Check for critical failures that warrant immediate high score
     */
    protected function hasCriticalFailure(array $checkResults): bool
    {
        // Blacklisted items
        foreach ($checkResults as $result) {
            if (! empty($result['details']['blacklisted'])) {
                return true;
            }
        }

        // Invalid credit card with high score
        if (isset($checkResults['credit_card']) &&
            $checkResults['credit_card']['score'] >= 100) {
            return true;
        }

        // Known malicious user agent
        if (isset($checkResults['user_agent']['details']['known_malicious'])) {
            return true;
        }

        return false;
    }

    /**
     * Detect patterns that indicate higher risk
     */
    protected function detectPatterns(array $checkResults): array
    {
        $patterns = [];

        // Pattern: Disposable email + Tor/VPN
        if ($this->hasDisposableEmail($checkResults) && $this->hasTorOrVPN($checkResults)) {
            $patterns['disposable_tor'] = 1.4; // 40% increase
        }

        // Pattern: New domain + High-risk IP
        if ($this->hasNewDomain($checkResults) && $this->hasHighRiskIP($checkResults)) {
            $patterns['new_domain_bad_ip'] = 1.25; // 25% increase
        }

        // Pattern: Test credit card + Bot user agent
        if ($this->hasTestCreditCard($checkResults) && $this->hasBotUserAgent($checkResults)) {
            $patterns['test_card_bot'] = 1.5; // 50% increase
        }

        // Pattern: Multiple location mismatches
        if ($this->hasLocationMismatches($checkResults) >= 2) {
            $patterns['location_mismatch'] = 1.3; // 30% increase
        }

        return $patterns;
    }

    /**
     * Check for velocity concerns across multiple data points
     */
    protected function hasVelocityConcerns(array $checkResults): bool
    {
        $velocityCount = 0;

        foreach ($checkResults as $result) {
            if (isset($result['details']['velocity']['risk_score']) &&
                $result['details']['velocity']['risk_score'] > 20) {
                $velocityCount++;
            }
        }

        return $velocityCount >= 2;
    }

    /**
     * Helper methods for pattern detection
     */
    protected function hasDisposableEmail(array $checkResults): bool
    {
        return ! empty($checkResults['email']['details']['disposable']);
    }

    protected function hasTorOrVPN(array $checkResults): bool
    {
        return ! empty($checkResults['ip']['details']['tor_exit_node']) ||
            ! empty($checkResults['ip']['details']['vpn_proxy']);
    }

    protected function hasNewDomain(array $checkResults): bool
    {
        $domainAge = $checkResults['domain']['details']['domain_age']['days'] ?? null;

        return $domainAge !== null && $domainAge < 30;
    }

    protected function hasHighRiskIP(array $checkResults): bool
    {
        return ($checkResults['ip']['score'] ?? 0) >= $this->thresholds['high'];
    }

    protected function hasTestCreditCard(array $checkResults): bool
    {
        return ! empty($checkResults['credit_card']['details']['test_card']);
    }

    protected function hasBotUserAgent(array $checkResults): bool
    {
        return ! empty($checkResults['user_agent']['details']['is_bot']) ||
            ! empty($checkResults['user_agent']['details']['automation_tool']);
    }

    protected function hasLocationMismatches(array $checkResults): int
    {
        $mismatches = 0;

        if (! empty($checkResults['ip']['details']['geo_consistency']['country_mismatch'])) {
            $mismatches++;
        }

        if (! empty($checkResults['phone']['details']['country_mismatch'])) {
            $mismatches++;
        }

        if (! empty($checkResults['ip']['details']['geo_consistency']['timezone_mismatch'])) {
            $mismatches++;
        }

        return $mismatches;
    }

    /**
     * Get risk level string from score
     */
    public function getRiskLevel(int $score): string
    {
        if ($score >= $this->thresholds['critical']) {
            return 'critical';
        } elseif ($score >= $this->thresholds['high']) {
            return 'high';
        } elseif ($score >= $this->thresholds['medium']) {
            return 'medium';
        } else {
            return 'low';
        }
    }

    /**
     * Get recommendation based on score
     */
    public function getRecommendation(int $score): string
    {
        $level = $this->getRiskLevel($score);

        return match ($level) {
            'critical' => 'Block immediately - Very high fraud risk detected',
            'high' => 'Manual review required - High fraud risk detected',
            'medium' => 'Additional verification recommended - Moderate fraud risk',
            'low' => 'Proceed with standard verification - Low fraud risk',
            default => 'Allow - Minimal fraud risk detected',
        };
    }
}
