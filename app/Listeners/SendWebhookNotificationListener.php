<?php

namespace App\Listeners;

use App\Events\FraudCheckPerformed;
use App\Events\FraudCheckPerformedEvent;
use App\Services\WebhookService;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Support\Facades\Log;

class SendWebhookNotificationListener implements ShouldQueue
{
    use InteractsWithQueue;

    /**
     * The number of times the job may be attempted.
     */
    public int $tries = 3;

    /**
     * The number of seconds to wait before retrying the job.
     *
     * @var array
     */
    public $backoff = [10, 30, 60];

    protected WebhookService $webhookService;

    /**
     * Create the event listener.
     */
    public function __construct(WebhookService $webhookService)
    {
        $this->webhookService = $webhookService;
    }

    /**
     * Handle the event.
     */
    public function handle(FraudCheckPerformedEvent $event): void
    {
        $user = $event->user;
        $result = $event->result;

        // Check if user has webhooks enabled
        if (! $this->shouldSendWebhook($user, $result)) {
            return;
        }

        // Get user's webhook configuration
        $webhookConfig = $this->getWebhookConfig($user);

        if (! $webhookConfig || ! $webhookConfig['url']) {
            return;
        }

        // Prepare webhook payload
        $payload = $this->preparePayload($event, $webhookConfig);

        // Dispatch webhook job
        \App\Jobs\SendWebhookJob::dispatch(
            $payload,
            $webhookConfig['url'],
            $webhookConfig['secret'] ?? null,
            [
                'user_id' => $user->id,
                'fraud_check_id' => $result['id'],
                'event_type' => 'fraud_check_performed',
            ]
        );

        Log::info('Webhook job dispatched', [
            'user_id' => $user->id,
            'fraud_check_id' => $result['id'],
            'webhook_url' => $webhookConfig['url'],
        ]);
    }

    /**
     * Determine if webhook should be sent.
     */
    protected function shouldSendWebhook($user, array $result): bool
    {
        // Only send webhooks for subscribed users
        if (! $user->subscribed('default')) {
            return false;
        }

        // Check if user's plan includes webhooks
        $plan = $user->getCurrentPlan();
        if (! in_array($plan, ['pro', 'enterprise'])) {
            return false;
        }

        // Check if event matches webhook criteria
        // For now, send for all checks or high-risk only based on config
        $webhookConfig = $this->getWebhookConfig($user);

        if (! $webhookConfig) {
            return false;
        }

        // Check event filters
        if (isset($webhookConfig['min_risk_score'])) {
            return $result['risk_score'] >= $webhookConfig['min_risk_score'];
        }

        return true;
    }

    /**
     * Get user's webhook configuration.
     */
    protected function getWebhookConfig($user): ?array
    {
        // This could be stored in user preferences or a separate table
        // For now, using a simple approach with user metadata

        return [
            'url' => $user->webhook_url ?? null,
            'secret' => $user->webhook_secret ?? null,
            'min_risk_score' => $user->webhook_min_risk_score ?? 0,
            'events' => $user->webhook_events ?? ['fraud_check.completed'],
        ];
    }

    /**
     * Prepare webhook payload.
     */
    protected function preparePayload(FraudCheckPerformed $event, array $config): array
    {
        $result = $event->result;
        $fraudCheck = \App\Models\FraudCheck::find($result['id']);

        return [
            'event' => 'fraud_check.completed',
            'timestamp' => now()->toIso8601String(),
            'data' => [
                'id' => $result['id'],
                'risk_score' => $result['risk_score'],
                'decision' => $result['decision'],
                'checks' => $result['checks'],
                'processing_time_ms' => $result['processing_time_ms'],
                'metadata' => [
                    'user_id' => $event->user->id,
                    'api_key_id' => $event->apiKey?->id,
                    'api_key_name' => $event->apiKey?->name,
                ],
            ],
        ];
    }

    /**
     * Handle a job failure.
     */
    public function failed(FraudCheckPerformed $event, \Throwable $exception): void
    {
        Log::error('Failed to send webhook after retries', [
            'user_id' => $event->user->id,
            'fraud_check_id' => $event->result['id'],
            'error' => $exception->getMessage(),
        ]);

        // Could notify user that webhook delivery failed
    }
}
