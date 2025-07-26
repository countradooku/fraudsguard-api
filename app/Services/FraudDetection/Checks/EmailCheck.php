<?php

namespace App\Services\FraudDetection\Checks;

use App\Models\BlacklistedEmail;
use App\Models\DisposableEmailDomain;
use App\Services\HashingService;
use Egulias\EmailValidator\EmailValidator;
use Egulias\EmailValidator\Validation\DNSCheckValidation;
use Egulias\EmailValidator\Validation\RFCValidation;
use Illuminate\Support\Facades\Cache;

class EmailCheck implements CheckInterface
{
    protected HashingService $hasher;

    protected EmailValidator $validator;

    protected array $roleAddresses = [
        'admin', 'support', 'info', 'contact', 'sales', 'help',
        'webmaster', 'postmaster', 'noreply', 'no-reply', 'donotreply',
        'abuse', 'spam', 'security', 'billing', 'legal', 'privacy',
    ];

    public function __construct(HashingService $hasher)
    {
        $this->hasher = $hasher;
        $this->validator = new EmailValidator;
    }

    public function applicable(array $data): bool
    {
        return ! empty($data['email']);
    }

    public function perform(array $data): array
    {
        $email = strtolower(trim($data['email']));
        $details = [];
        $score = 0;
        $passed = true;

        // 1. RFC 5322 validation
        if (! $this->validator->isValid($email, new RFCValidation)) {
            $details['rfc_validation'] = 'failed';
            $score += 100;
            $passed = false;

            return [
                'passed' => $passed,
                'score' => $score,
                'details' => $details,
            ];
        }
        $details['rfc_validation'] = 'passed';

        // Extract email parts
        [$localPart, $domain] = explode('@', $email);

        // 2. Check if blacklisted
        if ($this->isBlacklisted($email)) {
            $details['blacklisted'] = true;
            $score += 100;
            $passed = false;
        }

        // 3. Disposable email check
        if ($this->isDisposableEmail($domain)) {
            $details['disposable'] = true;
            $score += 80;
            $passed = false;
        }

        // 4. Role address check
        if ($this->isRoleAddress($localPart)) {
            $details['role_address'] = true;
            $score += 30;
        }

        // 5. Separator analysis
        $separatorAnalysis = $this->analyzeSeparators($localPart);
        $details['separators'] = $separatorAnalysis;
        $score += $separatorAnalysis['risk_score'];

        // 6. Tag check (e.g., user+tag@domain.com)
        if ($this->hasTag($localPart)) {
            $details['has_tag'] = true;
            $score += 20;
        }

        // 7. Composition check
        $compositionAnalysis = $this->analyzeComposition($localPart);
        $details['composition'] = $compositionAnalysis;
        $score += $compositionAnalysis['risk_score'];

        // 8. DNS validation (if not already failed)
        if ($score < 100) {
            if (! $this->validator->isValid($email, new DNSCheckValidation)) {
                $details['dns_validation'] = 'failed';
                $score += 50;
                $passed = false;
            } else {
                $details['dns_validation'] = 'passed';
            }
        }

        // 9. Email age and reputation (if available)
        $reputation = $this->checkReputation($email);
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

    protected function isBlacklisted(string $email): bool
    {
        $hash = $this->hasher->hash($email);

        return Cache::remember("blacklist:email:{$hash}", 300, function () use ($hash) {
            return BlacklistedEmail::where('email_hash', $hash)->exists();
        });
    }

    protected function isDisposableEmail(string $domain): bool
    {
        return Cache::remember("disposable:domain:{$domain}", 3600, function () use ($domain) {
            return DisposableEmailDomain::where('domain', $domain)
                ->where('is_active', true)
                ->exists();
        });
    }

    protected function isRoleAddress(string $localPart): bool
    {
        $localPart = strtolower($localPart);

        foreach ($this->roleAddresses as $role) {
            if ($localPart === $role || str_starts_with($localPart, $role.'.') ||
                str_starts_with($localPart, $role.'-') || str_starts_with($localPart, $role.'_')) {
                return true;
            }
        }

        return false;
    }

    protected function analyzeSeparators(string $localPart): array
    {
        $dots = substr_count($localPart, '.');
        $dashes = substr_count($localPart, '-');
        $underscores = substr_count($localPart, '_');
        $total = $dots + $dashes + $underscores;

        $riskScore = 0;

        // Multiple separators increase risk
        if ($total > 3) {
            $riskScore += 10;
        }
        if ($total > 5) {
            $riskScore += 15;
        }

        // Consecutive separators are suspicious
        if (preg_match('/[._-]{2,}/', $localPart)) {
            $riskScore += 20;
        }

        return [
            'dots' => $dots,
            'dashes' => $dashes,
            'underscores' => $underscores,
            'total' => $total,
            'risk_score' => $riskScore,
        ];
    }

    protected function hasTag(string $localPart): bool
    {
        return str_contains($localPart, '+');
    }

    protected function analyzeComposition(string $localPart): array
    {
        $length = strlen($localPart);
        $hasNumbers = preg_match('/\d/', $localPart);
        $numbersOnly = ctype_digit($localPart);
        $randomPattern = $this->detectRandomPattern($localPart);

        $riskScore = 0;

        // Very short or very long
        if ($length < 3) {
            $riskScore += 20;
        } elseif ($length > 30) {
            $riskScore += 15;
        }

        // Numbers only
        if ($numbersOnly) {
            $riskScore += 30;
        }

        // Random pattern
        if ($randomPattern) {
            $riskScore += 25;
        }

        return [
            'length' => $length,
            'has_numbers' => $hasNumbers,
            'numbers_only' => $numbersOnly,
            'random_pattern' => $randomPattern,
            'risk_score' => $riskScore,
        ];
    }

    protected function detectRandomPattern(string $localPart): bool
    {
        // Remove common separators
        $cleaned = str_replace(['.', '-', '_'], '', $localPart);

        // Check for random character sequences
        // High entropy suggests randomness
        if (strlen($cleaned) >= 8) {
            $uniqueChars = count(array_unique(str_split($cleaned)));
            $entropy = $uniqueChars / strlen($cleaned);

            // High entropy with mixed case and numbers
            if ($entropy > 0.8 && preg_match('/[a-z]/', $cleaned) &&
                preg_match('/[A-Z]/', $cleaned) && preg_match('/\d/', $cleaned)) {
                return true;
            }
        }

        // Check for common random patterns
        if (preg_match('/^[a-z0-9]{16,}$/i', $cleaned) ||
            preg_match('/^[a-f0-9]{16,}$/i', $cleaned)) {
            return true;
        }

        return false;
    }

    protected function checkReputation(string $email): ?array
    {
        // This would integrate with email reputation services
        // For now, check our own database

        $hash = $this->hasher->hash($email);

        $previousChecks = \App\Models\FraudCheck::where('email_hash', $hash)
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
            $riskScore += 20;
        }
        if ($blockCount > 2) {
            $riskScore += 30;
        }

        return [
            'previous_checks' => $previousChecks->count(),
            'avg_risk_score' => round($avgRiskScore, 2),
            'block_count' => $blockCount,
            'risk_score' => $riskScore,
        ];
    }
}
