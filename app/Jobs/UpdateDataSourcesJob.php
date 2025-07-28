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

    public int $tries = 2; // Reduced tries

    public int $timeout = 1200; // 20 minutes

    public int $memory = 512; // 512MB memory limit

    protected string $source;

    protected bool $force;

    public function __construct(string $source = 'all', bool $force = false)
    {
        $this->source = $source;
        $this->force = $force;

        // Set queue and memory requirements
        $this->onQueue('data-updates');
    }

    public function handle(): void
    {
        // Set memory and time limits
        ini_set('memory_limit', '512M');
        set_time_limit(1200);

        Log::info('Starting data source update', [
            'source' => $this->source,
            'force' => $this->force,
            'memory_limit' => ini_get('memory_limit'),
            'initial_memory' => memory_get_usage(true),
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
                    // Process one at a time to manage memory
                    $results['tor'] = $this->updateTorNodes();
                    gc_collect_cycles();

                    $results['disposable_emails'] = $this->updateDisposableEmails();
                    gc_collect_cycles();

                    $results['user_agents'] = $this->updateUserAgents();
                    gc_collect_cycles();

                    // ASN last as it's most memory intensive
                    $results['asn'] = $this->updateASN();
                    break;
            }

            Log::info('Data source update completed', [
                'source' => $this->source,
                'results' => $results,
                'peak_memory' => memory_get_peak_usage(true),
                'final_memory' => memory_get_usage(true),
            ]);

        } catch (\Exception $e) {
            Log::error('Data source update failed', [
                'source' => $this->source,
                'error' => $e->getMessage(),
                'memory_usage' => memory_get_usage(true),
                'peak_memory' => memory_get_peak_usage(true),
            ]);

            throw $e;
        }
    }

    protected function updateTorNodes(): array
    {
        try {
            $updater = app(TorExitNodeUpdater::class);

            return $updater->updateAll();
        } catch (\Exception $e) {
            Log::error('Failed to update Tor nodes', ['error' => $e->getMessage()]);

            return ['success' => false, 'error' => $e->getMessage()];
        } finally {
            gc_collect_cycles();
        }
    }

    protected function updateDisposableEmails(): array
    {
        try {
            $updater = app(DisposableEmailUpdater::class);

            return $updater->updateAll();
        } catch (\Exception $e) {
            Log::error('Failed to update disposable emails', ['error' => $e->getMessage()]);

            return ['success' => false, 'error' => $e->getMessage()];
        } finally {
            gc_collect_cycles();
        }
    }

    protected function updateASN(): array
    {
        try {
            $updater = app(ASNUpdater::class);

            return $updater->updateAll();
        } catch (\Exception $e) {
            Log::error('Failed to update ASN data', ['error' => $e->getMessage()]);

            return ['success' => false, 'error' => $e->getMessage()];
        } finally {
            gc_collect_cycles();
        }
    }

    protected function updateUserAgents(): array
    {
        try {
            $updater = app(UserAgentUpdater::class);

            return $updater->updateAll();
        } catch (\Exception $e) {
            Log::error('Failed to update user agents', ['error' => $e->getMessage()]);

            return ['success' => false, 'error' => $e->getMessage()];
        } finally {
            gc_collect_cycles();
        }
    }

    public function failed(\Throwable $exception): void
    {
        Log::error('Data source update job failed permanently', [
            'source' => $this->source,
            'error' => $exception->getMessage(),
            'memory_usage' => memory_get_usage(true),
            'peak_memory' => memory_get_peak_usage(true),
        ]);
    }
}
