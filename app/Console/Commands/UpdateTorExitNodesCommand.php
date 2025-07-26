<?php

namespace App\Console\Commands;

use App\Models\TorExitNode;
use Carbon\Carbon;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class UpdateTorExitNodesCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'fraud:update-tor-nodes
                            {--force : Force update even if recently updated}
                            {--clean : Remove inactive nodes}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Update the Tor exit nodes database from public sources';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $this->info('Starting Tor exit nodes update...');

        // Check if recently updated (unless forced)
        if (! $this->option('force')) {
            $lastUpdate = Carbon::parse(TorExitNode::max('updated_at'));
            if ($lastUpdate && $lastUpdate->diffInHours(now()) < 6) {
                $this->info('Tor nodes were recently updated. Use --force to update anyway.');

                return 0;
            }
        }

        try {
            // Fetch from multiple sources for reliability
            $nodes = $this->fetchTorNodes();

            if (empty($nodes)) {
                $this->error('No Tor nodes fetched from sources');

                return 1;
            }

            $this->info("Fetched {count($nodes)} Tor exit nodes");

            // Update database
            $this->updateDatabase($nodes);

            // Clean old nodes if requested
            if ($this->option('clean')) {
                $this->cleanInactiveNodes();
            }

            $this->info('Tor exit nodes update completed successfully');

            // Log the update
            Log::info('Tor exit nodes updated', [
                'count' => count($nodes),
                'timestamp' => now(),
            ]);

            return 0;

        } catch (\Exception $e) {
            $this->error('Error updating Tor nodes: '.$e->getMessage());
            Log::error('Tor update failed', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            return 1;
        }
    }

    /**
     * Fetch Tor nodes from various sources
     */
    protected function fetchTorNodes(): array
    {
        $nodes = [];

        // Source 1: TorProject.org exit list
        try {
            $this->info('Fetching from TorProject.org...');
            $response = Http::timeout(30)->get('https://check.torproject.org/torbulkexitlist');

            if ($response->successful()) {
                $ips = array_filter(explode("\n", $response->body()));
                foreach ($ips as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP)) {
                        $nodes[$ip] = [
                            'ip' => $ip,
                            'source' => 'torproject.org',
                        ];
                    }
                }
            }
        } catch (\Exception $e) {
            $this->warn('Failed to fetch from TorProject.org: '.$e->getMessage());
        }

        // Source 2: dan.me.uk Tor exit list
        try {
            $this->info('Fetching from dan.me.uk...');
            $response = Http::timeout(30)->get('https://www.dan.me.uk/torlist/?exit');

            if ($response->successful()) {
                $ips = array_filter(explode("\n", $response->body()));
                foreach ($ips as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP)) {
                        $nodes[$ip] = $nodes[$ip] ?? [
                            'ip' => $ip,
                            'source' => 'dan.me.uk',
                        ];
                    }
                }
            }
        } catch (\Exception $e) {
            $this->warn('Failed to fetch from dan.me.uk: '.$e->getMessage());
        }

        // Source 3: Onionoo API (more detailed data)
        try {
            $this->info('Fetching from Onionoo API...');
            $response = Http::timeout(30)->get('https://onionoo.torproject.org/details', [
                'type' => 'relay',
                'flag' => 'exit',
                'fields' => 'nickname,fingerprint,exit_addresses,last_seen',
            ]);

            if ($response->successful()) {
                $data = $response->json();
                foreach ($data['relays'] ?? [] as $relay) {
                    foreach ($relay['exit_addresses'] ?? [] as $address) {
                        $ip = explode(':', $address)[0]; // Remove port if present
                        if (filter_var($ip, FILTER_VALIDATE_IP)) {
                            $nodes[$ip] = [
                                'ip' => $ip,
                                'node_id' => $relay['fingerprint'] ?? null,
                                'nickname' => $relay['nickname'] ?? null,
                                'last_seen' => $relay['last_seen'] ?? null,
                                'source' => 'onionoo',
                            ];
                        }
                    }
                }
            }
        } catch (\Exception $e) {
            $this->warn('Failed to fetch from Onionoo: '.$e->getMessage());
        }

        return array_values($nodes);
    }

    /**
     * Update database with fetched nodes
     */
    protected function updateDatabase(array $nodes): void
    {
        $this->info('Updating database...');
        $bar = $this->output->createProgressBar(count($nodes));
        $bar->start();

        DB::beginTransaction();

        try {
            // Mark all existing nodes as inactive
            TorExitNode::query()->update(['is_active' => false]);

            // Batch insert/update
            $chunks = array_chunk($nodes, 100);

            foreach ($chunks as $chunk) {
                $data = [];

                foreach ($chunk as $node) {
                    $ipVersion = filter_var($node['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 'v4' : 'v6';

                    $data[] = [
                        'ip_address' => $node['ip'],
                        'ip_version' => $ipVersion,
                        'node_id' => $node['node_id'] ?? null,
                        'nickname' => $node['nickname'] ?? null,
                        'is_active' => true,
                        'last_seen_at' => $node['last_seen'] ?? now(),
                        'created_at' => now(),
                        'updated_at' => now(),
                    ];
                }

                // Upsert nodes
                TorExitNode::upsert(
                    $data,
                    ['ip_address'], // Unique key
                    ['ip_version', 'node_id', 'nickname', 'is_active', 'last_seen_at', 'updated_at']
                );

                $bar->advance(count($chunk));
            }

            DB::commit();
            $bar->finish();
            $this->newLine();

        } catch (\Exception $e) {
            DB::rollBack();
            throw $e;
        }
    }

    /**
     * Remove nodes that haven't been seen recently
     */
    protected function cleanInactiveNodes(): void
    {
        $this->info('Cleaning inactive nodes...');

        $deleted = TorExitNode::where('is_active', false)
            ->where('last_seen_at', '<', now()->subDays(30))
            ->delete();

        $this->info("Removed {$deleted} inactive nodes");
    }
}
