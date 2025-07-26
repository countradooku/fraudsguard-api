<?php

namespace App\Jobs;

use App\Events\FraudCheckPerformedEvent;
use App\Services\FraudDetection\FraudDetectionService;
use App\Events\FraudCheckPerformed;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

class ProcessFraudCheck implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    /**
     * The number of times the job may be attempted.
     *
     * @var int
     */
    public $tries = 3;

    /**
     * The number of seconds the job can run before timing out.
     *
     * @var int
     */
    public $timeout = 30;

    protected array $data;
    protected $user;
    protected $apiKey;

    /**
     * Create a new job instance.
     */
    public function __construct(array $data, $user, $apiKey = null)
    {
        $this->data = $data;
        $this->user = $user;
        $this->apiKey = $apiKey;
    }

    /**
     * Execute the job.
     */
    public function handle(FraudDetectionService $fraudService): void
    {
        try {
            // Perform fraud check
            $result = $fraudService->check($this->data, $this->user, $this->apiKey);

            // Dispatch event
            event(new FraudCheckPerformedEvent($this->user, $this->apiKey, $result));

            Log::info('Fraud check processed via queue', [
                'fraud_check_id' => $result['id'],
                'user_id' => $this->user->id,
                'risk_score' => $result['risk_score'],
            ]);
        } catch (\Exception $e) {
            Log::error('Failed to process fraud check', [
                'user_id' => $this->user->id,
                'error' => $e->getMessage(),
                'data' => $this->data,
            ]);

            throw $e; // Re-throw to trigger retry
        }
    }

    /**
     * Handle a job failure.
     */
    public function failed(\Throwable $exception): void
    {
        Log::error('Fraud check job failed permanently', [
            'user_id' => $this->user->id,
            'error' => $exception->getMessage(),
            'data' => $this->data,
        ]);

        // Could notify user or admin of failure
    }

    /**
     * Determine the time at which the job should timeout.
     */
    public function retryUntil(): \DateTime
    {
        return now()->addMinutes(10);
    }
}
