<?php

namespace App\Listeners;

use App\Events\FraudCheckPerformedEvent;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Redis;

class UpdateUsageStatsListener implements ShouldQueue
{
    use InteractsWithQueue;

    /**
     * Handle the event.
     */
    public function handle(FraudCheckPerformedEvent $event): void
    {
        $user = $event->user;
        $result = $event->result;

        // Update real-time statistics in Redis
        $this->updateRealtimeStats($user->id, $result);

        // Update cached statistics
        $this->updateCachedStats($user->id, $result);

        // Update rate limit counters
        $this->updateRateLimitCounters($event->apiKey, $result);
    }

    /**
     * Update real-time statistics in Redis.
     */
    protected function updateRealtimeStats(int $userId, array $result): void
    {
        $key = "stats:user:{$userId}";
        $today = date('Y-m-d');

        Redis::pipeline(function ($pipe) use ($key, $today, $result) {
            // Increment counters
            $pipe->hincrby($key, 'total_checks', 1);
            $pipe->hincrby($key, "daily:{$today}", 1);

            // Update risk score stats
            $pipe->hincrby($key, 'total_risk_score', $result['risk_score']);

            // Increment decision counters
            $pipe->hincrby($key, "decision:{$result['decision']}", 1);

            // Set expiry (30 days)
            $pipe->expire($key, 2592000);
        });
    }

    /**
     * Update cached statistics.
     */
    protected function updateCachedStats(int $userId, array $result): void
    {
        // Clear cached stats to force recalculation
        Cache::forget("user_stats:{$userId}:day");
        Cache::forget("user_stats:{$userId}:month");
        Cache::forget("user_stats:{$userId}:all");

        // Update high-risk counter if applicable
        if ($result['risk_score'] >= 80) {
            Cache::increment("high_risk_count:{$userId}");
        }
    }

    /**
     * Update rate limit counters.
     */
    protected function updateRateLimitCounters($apiKey, array $result): void
    {
        if (! $apiKey) {
            return;
        }

        $hour = date('YmdH');
        $minute = date('YmdHi');

        // Update hourly counter
        $hourKey = "rate_limit:{$apiKey->id}:hour:{$hour}";
        Redis::incr($hourKey);
        Redis::expire($hourKey, 3600);

        // Update minute counter for burst detection
        $minuteKey = "rate_limit:{$apiKey->id}:minute:{$minute}";
        Redis::incr($minuteKey);
        Redis::expire($minuteKey, 60);
    }
}
