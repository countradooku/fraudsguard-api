<?php

namespace App\Services\FraudDetection;

use App\Models\FraudCheck;
use App\Services\FraudDetection\Checks\CreditCardCheck;
use App\Services\FraudDetection\Checks\DomainCheck;
use App\Services\FraudDetection\Checks\EmailCheck;
use App\Services\FraudDetection\Checks\IPCheck;
use App\Services\FraudDetection\Checks\PhoneCheck;
use App\Services\FraudDetection\Checks\UserAgentCheck;
use App\Services\FraudDetection\Scorers\RiskScorer;
use App\Services\HashingService;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

class FraudDetectionService
{
    protected HashingService $hasher;

    protected RiskScorer $scorer;

    protected array $checks = [];

    public function __construct(
        HashingService $hasher,
        RiskScorer $scorer,
        EmailCheck $emailCheck,
        DomainCheck $domainCheck,
        IPCheck $ipCheck,
        CreditCardCheck $creditCardCheck,
        PhoneCheck $phoneCheck,
        UserAgentCheck $userAgentCheck
    ) {
        $this->hasher = $hasher;
        $this->scorer = $scorer;

        $this->checks = [
            'email' => $emailCheck,
            'domain' => $domainCheck,
            'ip' => $ipCheck,
            'credit_card' => $creditCardCheck,
            'phone' => $phoneCheck,
            'user_agent' => $userAgentCheck,
        ];
    }

    /**
     * Perform comprehensive fraud check
     */
    public function check(array $data, $user = null, $apiKey = null): array
    {
        $startTime = microtime(true);

        try {
            DB::beginTransaction();

            // Create fraud check record
            $fraudCheck = $this->createFraudCheckRecord($data, $user, $apiKey);

            // Run all applicable checks
            $checkResults = $this->runChecks($data);

            // Calculate risk score
            $riskScore = $this->scorer->calculateScore($checkResults);

            // Determine decision
            $decision = $this->makeDecision($riskScore, $checkResults);

            // Update fraud check record
            $fraudCheck->update([
                'risk_score' => $riskScore,
                'check_results' => $checkResults,
                'failed_checks' => $this->extractFailedChecks($checkResults),
                'passed_checks' => $this->extractPassedChecks($checkResults),
                'decision' => $decision,
                'processing_time_ms' => (int) ((microtime(true) - $startTime) * 1000),
            ]);

            // Store blacklist data if high risk
            if ($riskScore >= 80) {
                $this->storeBlacklistData($data, $checkResults, $user);
            }

            DB::commit();

            return [
                'risk_score' => $riskScore,
                'decision' => $decision,
                'checks' => $checkResults,
                'id' => $fraudCheck->id,
                'processing_time_ms' => $fraudCheck->processing_time_ms,
            ];

        } catch (\Exception $e) {
            DB::rollBack();
            Log::error('Fraud check failed', [
                'error' => $e->getMessage(),
                'data' => $data,
            ]);

            throw $e;
        }
    }

    /**
     * Create initial fraud check record
     */
    protected function createFraudCheckRecord(array $data, $user, $apiKey): FraudCheck
    {
        $record = [
            'user_id' => $user?->id,
            'api_key_id' => $apiKey?->id,
            'check_results' => [],
            'risk_score' => 0,
            'decision' => 'pending',
        ];

        // Hash and encrypt sensitive data
        if (! empty($data['email'])) {
            $record['email_hash'] = $this->hasher->hash($data['email']);
            $record['email_encrypted'] = Crypt::encryptString($data['email']);
        }

        if (! empty($data['ip'])) {
            $record['ip_hash'] = $this->hasher->hash($data['ip']);
            $record['ip_encrypted'] = Crypt::encryptString($data['ip']);
        }

        if (! empty($data['credit_card'])) {
            $record['credit_card_hash'] = $this->hasher->hash($data['credit_card']);
            $record['credit_card_encrypted'] = Crypt::encryptString($data['credit_card']);
        }

        if (! empty($data['phone'])) {
            $record['phone_hash'] = $this->hasher->hash($data['phone']);
            $record['phone_encrypted'] = Crypt::encryptString($data['phone']);
        }

        // Store metadata
        $record['user_agent'] = $data['user_agent'] ?? null;
        $record['domain'] = $data['domain'] ?? null;
        $record['headers'] = $data['headers'] ?? null;

        return FraudCheck::create($record);
    }

    /**
     * Run all applicable checks
     */
    protected function runChecks(array $data): array
    {
        $results = [];

        foreach ($this->checks as $name => $check) {
            if ($check->applicable($data)) {
                try {
                    $results[$name] = $check->perform($data);
                } catch (\Exception $e) {
                    Log::error("Check {$name} failed", ['error' => $e->getMessage()]);
                    $results[$name] = [
                        'passed' => false,
                        'score' => 50,
                        'details' => ['error' => 'Check failed to execute'],
                    ];
                }
            }
        }

        return $results;
    }

    /**
     * Make decision based on risk score
     */
    protected function makeDecision(int $riskScore, array $checkResults): string
    {
        if ($riskScore === 0) {
            return 'allow';
        } elseif ($riskScore >= 100) {
            return 'block';
        } elseif ($riskScore >= 80) {
            return 'block'; // High risk - auto block
        } elseif ($riskScore >= 50) {
            return 'review'; // Medium risk - manual review
        } else {
            return 'allow'; // Low risk - allow
        }
    }

    /**
     * Extract failed checks
     */
    protected function extractFailedChecks(array $checkResults): array
    {
        $failed = [];

        foreach ($checkResults as $name => $result) {
            if (! $result['passed']) {
                $failed[$name] = $result['details'] ?? [];
            }
        }

        return $failed;
    }

    /**
     * Extract passed checks
     */
    protected function extractPassedChecks(array $checkResults): array
    {
        $passed = [];

        foreach ($checkResults as $name => $result) {
            if ($result['passed']) {
                $passed[$name] = $result['details'] ?? [];
            }
        }

        return $passed;
    }

    /**
     * Store data in blacklists if high risk
     */
    protected function storeBlacklistData(array $data, array $checkResults, $user): void
    {
        // This would be implemented based on specific business rules
        // For example, automatically blacklist emails/IPs with very high risk scores

        if (! empty($data['email']) && ($checkResults['email']['score'] ?? 0) >= 80) {
            // Store in blacklisted_emails table
        }

        if (! empty($data['ip']) && ($checkResults['ip']['score'] ?? 0) >= 80) {
            // Store in blacklisted_ips table
        }
    }
}
