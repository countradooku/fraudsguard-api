<?php

namespace App\Console\Commands;

use App\Jobs\UpdateDataSourcesJob;
use Illuminate\Console\Command;

class UpdateDataSourcesCommand extends Command
{
    protected $signature = 'fraud:update-data-sources
                            {source=all : The data source to update (all, tor, disposable_emails, asn, user_agents)}
                            {--force : Force update even if recently updated}
                            {--sync : Run synchronously instead of queuing}
                            {--memory=512 : Memory limit in MB}';

    protected $description = 'Update fraud detection data sources';

    public function handle(): int
    {
        $source = $this->argument('source');
        $force = $this->option('force');
        $sync = $this->option('sync');
        $memoryLimit = $this->option('memory') . 'M';

        // Set memory limit
        ini_set('memory_limit', $memoryLimit);

        $validSources = ['all', 'tor', 'disposable_emails', 'asn', 'user_agents'];
        if (!in_array($source, $validSources)) {
            $this->error('Invalid source. Valid sources: ' . implode(', ', $validSources));
            return 1;
        }

        $this->info("Updating data source: {$source} (Memory limit: {$memoryLimit})");

        if ($sync) {
            try {
                $job = new UpdateDataSourcesJob($source, $force);
                $job->handle();

                $this->info('Data source update completed successfully');
                $this->line('Peak memory usage: ' . $this->formatBytes(memory_get_peak_usage(true)));

                return 0;
            } catch (\Exception $e) {
                $this->error('Data source update failed: ' . $e->getMessage());
                $this->line('Peak memory usage: ' . $this->formatBytes(memory_get_peak_usage(true)));

                return 1;
            }
        } else {
            UpdateDataSourcesJob::dispatch($source, $force);
            $this->info('Data source update job queued');
            return 0;
        }
    }

    private function formatBytes(int $size, int $precision = 2): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];

        for ($i = 0; $size > 1024 && $i < count($units) - 1; $i++) {
            $size /= 1024;
        }

        return round($size, $precision) . ' ' . $units[$i];
    }
}
