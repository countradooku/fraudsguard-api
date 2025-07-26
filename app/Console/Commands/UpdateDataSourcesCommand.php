<?php

namespace App\Console\Commands;

use App\Jobs\UpdateDataSourcesJob;
use Illuminate\Console\Command;

class UpdateDataSourcesCommand extends Command
{
    /**
     * The name and signature of the console command.
     */
    protected $signature = 'fraud:update-data-sources
                            {source=all : The data source to update (all, tor, disposable_emails, asn, user_agents)}
                            {--force : Force update even if recently updated}
                            {--sync : Run synchronously instead of queuing}';

    /**
     * The console command description.
     */
    protected $description = 'Update fraud detection data sources';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        ini_set('memory_limit', '1024M');
        $source = $this->argument('source');
        $force = $this->option('force');
        $sync = $this->option('sync');

        // Validate source
        $validSources = ['all', 'tor', 'disposable_emails', 'asn', 'user_agents'];
        if (! in_array($source, $validSources)) {
            $this->error('Invalid source. Valid sources: '.implode(', ', $validSources));

            return 1;
        }

        $this->info("Updating data source: {$source}");

        if ($sync) {
            // Run synchronously
            try {
                $job = new UpdateDataSourcesJob($source, $force);
                $job->handle();

                $this->info('Data source update completed successfully');

                return 0;
            } catch (\Exception $e) {
                $this->error('Data source update failed: '.$e->getMessage());

                return 1;
            }
        } else {
            // Queue the job
            UpdateDataSourcesJob::dispatch($source, $force);
            $this->info('Data source update job queued');

            return 0;
        }
    }
}
