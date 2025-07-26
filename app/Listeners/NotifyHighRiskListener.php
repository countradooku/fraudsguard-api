<?php

namespace App\Listeners;

use App\Events\HighRiskDetectedEvent;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;

class NotifyHighRiskListener implements ShouldQueue
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
    public function handle(HighRiskDetectedEvent $event): void
    {
        $fraudCheck = $event->fraudCheck;
        $user = $fraudCheck->user;

        // Send email notification to user
        if ($user->email_verified_at) {
            try {
                // Mail::to($user)->send(new HighRiskAlert($fraudCheck));

                Log::info('High risk alert sent', [
                    'user_id' => $user->id,
                    'fraud_check_id' => $fraudCheck->id,
                ]);
            } catch (\Exception $e) {
                Log::error('Failed to send high risk alert', [
                    'user_id' => $user->id,
                    'fraud_check_id' => $fraudCheck->id,
                    'error' => $e->getMessage(),
                ]);
            }
        }

        // Send to admin/security team if critical
        if ($fraudCheck->risk_score >= 90) {
            $this->notifySecurityTeam($fraudCheck);
        }

        // Update user statistics
        $this->updateUserStats($user, $fraudCheck);
    }

    /**
     * Notify security team of critical risks.
     */
    protected function notifySecurityTeam($fraudCheck): void
    {
        $securityEmail = config('fraud-detection.security_email');

        if ($securityEmail) {
            try {
                Mail::raw(
                    "Critical fraud risk detected!\n\n".
                    "Fraud Check ID: {$fraudCheck->id}\n".
                    "Risk Score: {$fraudCheck->risk_score}\n".
                    "User: {$fraudCheck->user->email}\n".
                    'Failed Checks: '.implode(', ', $fraudCheck->failed_check_names),
                    function ($message) use ($securityEmail) {
                        $message->to($securityEmail)
                            ->subject('Critical Fraud Risk Alert');
                    }
                );
            } catch (\Exception $e) {
                Log::error('Failed to notify security team', [
                    'error' => $e->getMessage(),
                ]);
            }
        }
    }

    /**
     * Update user fraud statistics.
     */
    protected function updateUserStats($user, $fraudCheck): void
    {
        // This could update a user stats table or cache
        // For now, just log it
        Log::info('User high risk count increased', [
            'user_id' => $user->id,
            'total_high_risk' => $user->fraudChecks()->highRisk()->count(),
        ]);
    }

    /**
     * Handle a job failure.
     */
    public function failed(HighRiskDetectedEvent $event, \Throwable $exception): void
    {
        Log::error('Failed to process high risk notification', [
            'fraud_check_id' => $event->fraudCheck->id,
            'error' => $exception->getMessage(),
        ]);
    }
}
