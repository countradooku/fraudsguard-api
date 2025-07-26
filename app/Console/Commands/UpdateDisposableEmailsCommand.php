<?php

namespace App\Console\Commands;

use App\Models\DisposableEmailDomain;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class UpdateDisposableEmailsCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'fraud:update-disposable-emails
                            {--force : Force update even if recently updated}
                            {--source=all : Update from specific source (all, github, custom)}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Update the disposable email domains database from public sources';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $this->info('Starting disposable email domains update...');

        // Check if recently updated (unless forced)
        if (! $this->option('force')) {
            $lastUpdate = DisposableEmailDomain::max('updated_at');
            if ($lastUpdate && $lastUpdate->diffInHours(now()) < 24) {
                $this->info('Disposable domains were recently updated. Use --force to update anyway.');

                return 0;
            }
        }

        try {
            $domains = [];
            $source = $this->option('source');

            if ($source === 'all' || $source === 'github') {
                $domains = array_merge($domains, $this->fetchFromGitHub());
            }

            if ($source === 'all' || $source === 'custom') {
                $domains = array_merge($domains, $this->fetchFromCustomSources());
            }

            // Remove duplicates
            $domains = array_unique($domains);

            if (empty($domains)) {
                $this->error('No domains fetched from sources');

                return 1;
            }

            $this->info('Fetched '.count($domains).' disposable email domains');

            // Update database
            $this->updateDatabase($domains);

            $this->info('Disposable email domains update completed successfully');

            // Log the update
            Log::info('Disposable email domains updated', [
                'count' => count($domains),
                'timestamp' => now(),
            ]);

            return 0;

        } catch (\Exception $e) {
            $this->error('Error updating disposable domains: '.$e->getMessage());
            Log::error('Disposable domains update failed', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            return 1;
        }
    }

    /**
     * Fetch domains from GitHub repositories
     */
    protected function fetchFromGitHub(): array
    {
        $domains = [];

        // Popular disposable email lists on GitHub
        $sources = [
            'https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf',
            'https://raw.githubusercontent.com/FGRibreau/mailchecker/master/list.txt',
            'https://raw.githubusercontent.com/wesbos/burner-email-providers/master/emails.txt',
            'https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/index.json',
        ];

        foreach ($sources as $source) {
            try {
                $this->info('Fetching from: '.parse_url($source, PHP_URL_HOST));

                $response = Http::timeout(30)->get($source);

                if ($response->successful()) {
                    $content = $response->body();

                    // Handle JSON format
                    if (str_ends_with($source, '.json')) {
                        $data = json_decode($content, true);
                        if (is_array($data)) {
                            $domains = array_merge($domains, $data);
                        }
                    } else {
                        // Handle text format (one domain per line)
                        $lines = explode("\n", $content);
                        foreach ($lines as $line) {
                            $domain = trim($line);
                            if ($domain && ! str_starts_with($domain, '#') && $this->isValidDomain($domain)) {
                                $domains[] = $domain;
                            }
                        }
                    }
                }
            } catch (\Exception $e) {
                $this->warn('Failed to fetch from source: '.$e->getMessage());
            }
        }

        return $domains;
    }

    /**
     * Fetch from custom/proprietary sources
     */
    protected function fetchFromCustomSources(): array
    {
        $domains = [];

        // Add any custom sources here
        // For example, your own curated list or paid APIs

        return $domains;
    }

    /**
     * Validate domain format
     */
    protected function isValidDomain(string $domain): bool
    {
        // Basic domain validation
        return preg_match('/^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i', $domain);
    }

    /**
     * Update database with fetched domains
     *
     * @throws \Exception
     */
    protected function updateDatabase(array $domains): void
    {
        $this->info('Updating database...');
        $bar = $this->output->createProgressBar(count($domains));
        $bar->start();

        DB::beginTransaction();

        try {
            // Mark all existing domains as inactive
            DisposableEmailDomain::query()->update(['is_active' => false]);

            // Batch insert/update
            $chunks = array_chunk($domains, 500);

            foreach ($chunks as $chunk) {
                $data = [];

                foreach ($chunk as $domain) {
                    $data[] = [
                        'domain' => strtolower($domain),
                        'source' => 'automated',
                        'is_active' => true,
                        'verified_at' => now(),
                        'created_at' => now(),
                        'updated_at' => now(),
                    ];
                }

                // Upsert domains
                DisposableEmailDomain::upsert(
                    $data,
                    ['domain'], // Unique key
                    ['is_active', 'verified_at', 'updated_at']
                );

                $bar->advance(count($chunk));
            }

            // Remove domains that haven't been seen in multiple updates
            $deleted = DisposableEmailDomain::where('is_active', false)
                ->where('updated_at', '<', now()->subDays(7))
                ->delete();

            if ($deleted > 0) {
                $this->info("\nRemoved {$deleted} obsolete domains");
            }

            DB::commit();
            $bar->finish();
            $this->newLine();

        } catch (\Exception $e) {
            DB::rollBack();
            throw $e;
        }
    }
}
