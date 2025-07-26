<?php

namespace App\Jobs;

use App\Services\WebhookService;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

class SendWebhookJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    /**
     * The number of times the job may be attempted.
     */
    public int $tries = 3;

    /**
     * The number of seconds to wait before retrying the job.
     */
    public array $backoff = [10, 30, 60];

    protected array $payload;
    protected string $url;
    protected ?string $secret;
    protected array $metadata;

    /**
     * Create a new job instance.
     */
    public function __construct(array $payload, string $url, ?string $secret = null, array $metadata = [])
    {
        $this->payload = $payload;
        $this->url = $url;
        $this->secret = $secret;
        $this->metadata = $metadata;
    }

    /**
     * Execute the job.
     */
    public function handle(WebhookService $webhookService): void
    {
        try {
            $response = $webhookService->send($this->url, $this->payload, $this->secret);

            Log::info('Webhook sent successfully', [
                'url' => $this->url,
                'event' => $this->payload['event'] ?? 'unknown',
                'response_code' => $response['status_code'],
                'metadata' => $this->metadata,
            ]);

        } catch (\Exception $e) {
            Log::error('Webhook delivery failed', [
                'url' => $this->url,
                'event' => $this->payload['event'] ?? 'unknown',
                'error' => $e->getMessage(),
                'attempt' => $this->attempts(),
                'metadata' => $this->metadata,
            ]);

            // Re-throw to trigger retry
            throw $e;
        }
    }

    /**
     * Handle a job failure.
     */
    public function failed(\Throwable $exception): void
    {
        Log::error('Webhook delivery failed permanently', [
            'url' => $this->url,
            'event' => $this->payload['event'] ?? 'unknown',
            'error' => $exception->getMessage(),
            'metadata' => $this->metadata,
        ]);

        // Could notify user about webhook failure
        // or update webhook status in database
    }

    /**
     * Determine the time at which the job should timeout.
     */
    public function retryUntil(): \DateTime
    {
        return now()->addMinutes(15);
    }
}
