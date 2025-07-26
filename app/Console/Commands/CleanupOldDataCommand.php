<?php

namespace App\Console\Commands;

use App\Models\ApiUsage;
use App\Models\BlacklistedCreditCard;
use App\Models\BlacklistedEmail;
use App\Models\BlacklistedIP;
use App\Models\BlacklistedPhone;
use App\Models\FraudCheck;
use Carbon\Carbon;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

class CleanupOldDataCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'fraud:cleanup-old-data
                            {--dry-run : Show what would be deleted without actually deleting}
                            {--force : Force cleanup without confirmation}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Clean up old fraud detection data based on retention policies';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $dryRun = $this->option('dry-run');
        $force = $this->option('force');

        if (! $force && ! $dryRun && ! $this->confirm('Are you sure you want to clean up old data? This cannot be undone.')) {
            return 0;
        }

        $this->info('Starting data cleanup...');

        try {
            DB::beginTransaction();

            // Clean fraud checks
            $fraudChecksDeleted = $this->cleanFraudChecks($dryRun);

            // Clean API usage logs
            $apiUsageDeleted = $this->cleanApiUsage($dryRun);

            // Clean blacklist entries
            $blacklistDeleted = $this->cleanBlacklists($dryRun);

            // Clean expired Tor nodes
            $torNodesDeleted = $this->cleanTorNodes($dryRun);

            if ($dryRun) {
                DB::rollBack();
                $this->info('Dry run completed. No data was deleted.');
            } else {
                DB::commit();
                $this->info('Data cleanup completed successfully.');
            }

            // Show summary
            $this->table(
                ['Data Type', 'Records Deleted'],
                [
                    ['Fraud Checks', $fraudChecksDeleted],
                    ['API Usage Logs', $apiUsageDeleted],
                    ['Blacklist Entries', $blacklistDeleted],
                    ['Tor Exit Nodes', $torNodesDeleted],
                ]
            );

            // Log the cleanup
            if (! $dryRun) {
                Log::info('Data cleanup completed', [
                    'fraud_checks_deleted' => $fraudChecksDeleted,
                    'api_usage_deleted' => $apiUsageDeleted,
                    'blacklist_deleted' => $blacklistDeleted,
                    'tor_nodes_deleted' => $torNodesDeleted,
                ]);
            }

            return 0;

        } catch (\Exception $e) {
            DB::rollBack();
            $this->error('Error during cleanup: '.$e->getMessage());
            Log::error('Data cleanup failed', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            return 1;
        }
    }

    /**
     * Clean old fraud checks.
     */
    protected function cleanFraudChecks(bool $dryRun): int
    {
        $retentionDays = config('fraud-detection.data_retention.fraud_checks', 365);
        $cutoffDate = Carbon::now()->subDays($retentionDays);

        $this->info("Cleaning fraud checks older than {$retentionDays} days...");

        $query = FraudCheck::where('created_at', '<', $cutoffDate);
        $count = $query->count();

        if (! $dryRun && $count > 0) {
            $query->delete();
        }

        return $count;
    }

    /**
     * Clean old API usage logs.
     */
    protected function cleanApiUsage(bool $dryRun): int
    {
        $retentionDays = config('fraud-detection.data_retention.api_usage', 90);
        $cutoffDate = Carbon::now()->subDays($retentionDays);

        $this->info("Cleaning API usage logs older than {$retentionDays} days...");

        $query = ApiUsage::where('created_at', '<', $cutoffDate);
        $count = $query->count();

        if (! $dryRun && $count > 0) {
            // Delete in chunks to avoid memory issues
            $deleted = 0;
            $query->chunkById(1000, function ($logs) use (&$deleted) {
                $deleted += $logs->count();
                ApiUsage::whereIn('id', $logs->pluck('id'))->delete();
            });

            return $deleted;
        }

        return $count;
    }

    /**
     * Clean old blacklist entries.
     */
    protected function cleanBlacklists(bool $dryRun): int
    {
        $retentionDays = config('fraud-detection.data_retention.blacklist_entries', 180);
        $cutoffDate = Carbon::now()->subDays($retentionDays);

        $this->info("Cleaning blacklist entries older than {$retentionDays} days...");

        $totalDeleted = 0;

        // Clean blacklisted emails
        $emailQuery = BlacklistedEmail::where('last_seen_at', '<', $cutoffDate)
            ->where('report_count', '<', 5);
        $emailCount = $emailQuery->count();
        if (! $dryRun && $emailCount > 0) {
            $emailQuery->delete();
        }
        $totalDeleted += $emailCount;

        // Clean blacklisted IPs
        $ipQuery = BlacklistedIP::where('last_seen_at', '<', $cutoffDate)
            ->where('risk_weight', '<', 50);
        $ipCount = $ipQuery->count();
        if (! $dryRun && $ipCount > 0) {
            $ipQuery->delete();
        }
        $totalDeleted += $ipCount;

        // Clean blacklisted credit cards
        $cardQuery = BlacklistedCreditCard::where('last_seen_at', '<', $cutoffDate)
            ->where('chargeback_count', '=', 0);
        $cardCount = $cardQuery->count();
        if (! $dryRun && $cardCount > 0) {
            $cardQuery->delete();
        }
        $totalDeleted += $cardCount;

        // Clean blacklisted phones
        $phoneQuery = BlacklistedPhone::where('last_seen_at', '<', $cutoffDate);
        $phoneCount = $phoneQuery->count();
        if (! $dryRun && $phoneCount > 0) {
            $phoneQuery->delete();
        }
        $totalDeleted += $phoneCount;

        return $totalDeleted;
    }

    /**
     * Clean expired Tor nodes.
     */
    protected function cleanTorNodes(bool $dryRun): int
    {
        $cutoffDate = Carbon::now()->subDays(7);

        $this->info('Cleaning Tor nodes not seen in 7 days...');

        $query = \App\Models\TorExitNode::where('last_seen_at', '<', $cutoffDate)
            ->where('is_active', false);
        $count = $query->count();

        if (! $dryRun && $count > 0) {
            $query->delete();
        }

        return $count;
    }
}
