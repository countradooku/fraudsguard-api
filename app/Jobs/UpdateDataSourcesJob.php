<?php

namespace App\Jobs;

use App\Services\FraudDetection\DataSources\ASNUpdater;
use App\Services\FraudDetection\DataSources\DisposableEmailUpdater;
use App\Services\FraudDetection\DataSources\TorExitNodeUpdater;
use App\Services\FraudDetection\DataSources\UserAgentUpdater;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

class UpdateDataSourcesJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    /**
     * The number of times the job may be attempted.
     */
    public int $tries = 3;

    /**
     * The number of seconds the job can run before timing out.
     */
    public int $timeout = 600; // 10 minutes

    protected string $source;
    protected bool $force;

    /**
     * Create a new job instance.
     */
    public function __construct(string $source = 'all', bool $force = false)
    {
        $this->source = $source;
        $this->force = $force;
    }

    /**
     * Execute the job.
     */
    public function handle(): void
    {
        Log::info('Starting data source update', [
            'source' => $this->source,
            'force' => $this->force,
        ]);

        try {
            $results = [];

            switch ($this->source) {
                case 'tor':
                    $results['tor'] = $this->updateTorNodes();
                    break;
                case 'disposable_emails':
                    $results['disposable_emails'] = $this->updateDisposableEmails();
                    break;
                case 'asn':
                    $results['asn'] = $this->updateASN();
                    break;
                case 'user_agents':
                    $results['user_agents'] = $this->updateUserAgents();
                    break;
                case 'all':
                default:
                    $results['tor'] = $this->updateTorNodes();
                    $results['disposable_emails'] = $this->updateDisposableEmails();
                    $results['asn'] = $this->updateASN();
                    $results['user_agents'] = $this->updateUserAgents();
                    break;
            }

            Log::info('Data source update completed', [
                'source' => $this->source,
                'results' => $results,
            ]);

        } catch (\Exception $e) {
            Log::error('Data source update failed', [
                'source' => $this->source,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            throw $e;
        }
    }

    /**
     * Update Tor exit nodes.
     */
    protected function updateTorNodes(): array
    {
        try {
            $updater = app(TorExitNodeUpdater::class);
            return $updater->updateAll();
        } catch (\Exception $e) {
            Log::error('Failed to update Tor nodes', ['error' => $e->getMessage()]);
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Update disposable email domains.
     */
    protected function updateDisposableEmails(): array
    {
        try {
            $updater = app(DisposableEmailUpdater::class);
            return $updater->updateAll();
        } catch (\Exception $e) {
            Log::error('Failed to update disposable emails', ['error' => $e->getMessage()]);
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Update ASN database.
     */
    protected function updateASN(): array
    {
        try {
            $updater = app(ASNUpdater::class);
            return $updater->updateAll();
        } catch (\Exception $e) {
            Log::error('Failed to update ASN data', ['error' => $e->getMessage()]);
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Update user agents database.
     */
    protected function updateUserAgents(): array
    {
        try {
            $updater = app(UserAgentUpdater::class);
            return $updater->updateAll();
        } catch (\Exception $e) {
            Log::error('Failed to update user agents', ['error' => $e->getMessage()]);
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Handle a job failure.
     */
    public function failed(\Throwable $exception): void
    {
        Log::error('Data source update job failed permanently', [
            'source' => $this->source,
            'error' => $exception->getMessage(),
        ]);
    }
}
