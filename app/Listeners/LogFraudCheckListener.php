<?php

namespace App\Listeners;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Support\Facades\Log;

class LogFraudCheckListener implements ShouldQueue
{
    use InteractsWithQueue;

    /**
     * The number of times the job may be attempted.
     *
     * @var int
     */
    public $tries = 3;

    /**
     * Handle the event.
     */
    public function handle(FraudCheckPerformed $event): void
    {
        $result = $event->result;
        $user = $event->user;
        $apiKey = $event->apiKey;

        // Log basic info
        Log::channel('fraud-detection')->info('Fraud check performed', [
            'fraud_check_id' => $result['id'],
            'user_id' => $user->id,
            'api_key_id' => $apiKey?->id,
            'risk_score' => $result['risk_score'],
            'decision' => $result['decision'],
            'processing_time_ms' => $result['processing_time_ms'],
        ]);

        // Log high-risk checks separately
        if ($result['risk_score'] >= 80) {
            Log::channel('fraud-detection')->warning('High risk detected', [
                'fraud_check_id' => $result['id'],
                'user_id' => $user->id,
                'risk_score' => $result['risk_score'],
                'failed_checks' => array_keys($result['checks'] ?? []),
            ]);
        }

        // Log performance issues
        if ($result['processing_time_ms'] > 1000) {
            Log::channel('fraud-detection')->warning('Slow fraud check', [
                'fraud_check_id' => $result['id'],
                'processing_time_ms' => $result['processing_time_ms'],
            ]);
        }
    }

    /**
     * Handle a job failure.
     */
    public function failed(FraudCheckPerformed $event, \Throwable $exception): void
    {
        Log::channel('fraud-detection')->error('Failed to log fraud check', [
            'fraud_check_id' => $event->result['id'] ?? null,
            'error' => $exception->getMessage(),
        ]);
    }
}
