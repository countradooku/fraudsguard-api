<?php

namespace App\Http\Controllers;

use Carbon\Carbon;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

class DashboardController extends Controller
{
    /**
     * Get dashboard statistics.
     */
    public function index(Request $request): JsonResponse
    {
        $user = $request->user();

        // Get cached stats or calculate
        $stats = Cache::remember("user_dashboard:{$user->id}", 300, function () use ($user) {
            return $this->calculateDashboardStats($user);
        });

        // Get real-time data (not cached)
        $realtimeData = $this->getRealtimeData($user);

        return response()->json([
            'success' => true,
            'data' => array_merge($stats, $realtimeData),
        ]);
    }

    /**
     * Get fraud check statistics.
     */
    public function fraudStats(Request $request): JsonResponse
    {
        $request->validate([
            'period' => 'string|in:hour,day,week,month,year',
            'group_by' => 'string|in:hour,day,week,month',
        ]);

        $user = $request->user();
        $period = $request->input('period', 'month');
        $groupBy = $request->input('group_by', 'day');

        $stats = $this->getFraudCheckStats($user, $period, $groupBy);

        return response()->json([
            'success' => true,
            'data' => $stats,
        ]);
    }

    /**
     * Get usage analytics.
     */
    public function analytics(Request $request): JsonResponse
    {
        $request->validate([
            'start_date' => 'date',
            'end_date' => 'date|after_or_equal:start_date',
            'metrics' => 'array',
            'metrics.*' => 'string|in:api_calls,fraud_checks,risk_scores,response_times,costs',
        ]);

        $user = $request->user();
        $startDate = $request->input('start_date', now()->subDays(30));
        $endDate = $request->input('end_date', now());
        $metrics = $request->input('metrics', ['api_calls', 'fraud_checks', 'risk_scores']);

        $analytics = $this->getAnalytics($user, $startDate, $endDate, $metrics);

        return response()->json([
            'success' => true,
            'data' => $analytics,
        ]);
    }

    /**
     * Get recent activity.
     */
    public function recentActivity(Request $request): JsonResponse
    {
        $request->validate([
            'limit' => 'integer|min:1|max:100',
            'type' => 'string|in:all,fraud_checks,api_calls,high_risk',
        ]);

        $user = $request->user();
        $limit = $request->input('limit', 10);
        $type = $request->input('type', 'all');

        $activity = $this->getRecentActivity($user, $limit, $type);

        return response()->json([
            'success' => true,
            'data' => $activity,
        ]);
    }

    /**
     * Calculate dashboard statistics.
     */
    protected function calculateDashboardStats($user): array
    {
        // Get current billing period
        $billingPeriod = $this->getBillingPeriod($user);

        // Fraud check statistics
        $fraudStats = $user->fraudChecks()
            ->whereBetween('created_at', $billingPeriod)
            ->selectRaw('
                COUNT(*) as total_checks,
                AVG(risk_score) as avg_risk_score,
                MAX(risk_score) as max_risk_score,
                SUM(CASE WHEN decision = \'allow\' THEN 1 ELSE 0 END) as allowed,
                SUM(CASE WHEN decision = \'review\' THEN 1 ELSE 0 END) as review,
                SUM(CASE WHEN decision = \'block\' THEN 1 ELSE 0 END) as blocked,
                AVG(processing_time_ms) as avg_processing_time
            ')
            ->first();

        // API usage statistics
        $apiStats = $user->apiUsage()
            ->whereBetween('created_at', $billingPeriod)
            ->selectRaw('
                COUNT(*) as total_requests,
                SUM(CASE WHEN response_code >= 200 AND response_code < 300 THEN 1 ELSE 0 END) as successful_requests,
                SUM(CASE WHEN is_billable THEN 1 ELSE 0 END) as billable_requests,
                SUM(CASE WHEN is_over_limit THEN 1 ELSE 0 END) as overage_requests,
                SUM(cost) as total_cost
            ')
            ->first();

        // Check type distribution
        $checkTypes = $user->fraudChecks()
            ->whereBetween('created_at', $billingPeriod)
            ->selectRaw('
                SUM(CASE WHEN email_hash IS NOT NULL THEN 1 ELSE 0 END) as email_checks,
                SUM(CASE WHEN ip_hash IS NOT NULL THEN 1 ELSE 0 END) as ip_checks,
                SUM(CASE WHEN credit_card_hash IS NOT NULL THEN 1 ELSE 0 END) as credit_card_checks,
                SUM(CASE WHEN phone_hash IS NOT NULL THEN 1 ELSE 0 END) as phone_checks
            ')
            ->first();

        // Risk score distribution
        $riskDistribution = $user->fraudChecks()
            ->whereBetween('created_at', $billingPeriod)
            ->selectRaw('
                SUM(CASE WHEN risk_score < 30 THEN 1 ELSE 0 END) as low_risk,
                SUM(CASE WHEN risk_score >= 30 AND risk_score < 50 THEN 1 ELSE 0 END) as medium_risk,
                SUM(CASE WHEN risk_score >= 50 AND risk_score < 80 THEN 1 ELSE 0 END) as high_risk,
                SUM(CASE WHEN risk_score >= 80 THEN 1 ELSE 0 END) as critical_risk
            ')
            ->first();

        return [
            'billing_period' => [
                'start' => $billingPeriod[0]->toIso8601String(),
                'end' => $billingPeriod[1]->toIso8601String(),
            ],
            'fraud_checks' => [
                'total' => $fraudStats->total_checks ?? 0,
                'average_risk_score' => round($fraudStats->avg_risk_score ?? 0, 2),
                'max_risk_score' => $fraudStats->max_risk_score ?? 0,
                'decisions' => [
                    'allowed' => $fraudStats->allowed ?? 0,
                    'review' => $fraudStats->review ?? 0,
                    'blocked' => $fraudStats->blocked ?? 0,
                ],
                'average_processing_time' => round($fraudStats->avg_processing_time ?? 0, 2),
            ],
            'api_usage' => [
                'total_requests' => $apiStats->total_requests ?? 0,
                'successful_requests' => $apiStats->successful_requests ?? 0,
                'billable_requests' => $apiStats->billable_requests ?? 0,
                'overage_requests' => $apiStats->overage_requests ?? 0,
                'total_cost' => round($apiStats->total_cost ?? 0, 2),
                'success_rate' => $apiStats->total_requests > 0
                    ? round(($apiStats->successful_requests / $apiStats->total_requests) * 100, 2)
                    : 0,
            ],
            'check_types' => [
                'email' => $checkTypes->email_checks ?? 0,
                'ip' => $checkTypes->ip_checks ?? 0,
                'credit_card' => $checkTypes->credit_card_checks ?? 0,
                'phone' => $checkTypes->phone_checks ?? 0,
            ],
            'risk_distribution' => [
                'low' => $riskDistribution->low_risk ?? 0,
                'medium' => $riskDistribution->medium_risk ?? 0,
                'high' => $riskDistribution->high_risk ?? 0,
                'critical' => $riskDistribution->critical_risk ?? 0,
            ],
        ];
    }

    /**
     * Get real-time data.
     */
    protected function getRealtimeData($user): array
    {
        return [
            'current_usage' => [
                'today' => $user->apiUsage()->whereDate('created_at', today())->count(),
                'this_hour' => $user->apiUsage()->where('created_at', '>=', now()->startOfHour())->count(),
                'rate_limit' => $user->getRateLimit(),
                'rate_limit_remaining' => max(0, $user->getRateLimit() - $user->apiUsage()->where('created_at', '>=', now()->startOfHour())->count()),
            ],
            'subscription' => [
                'plan' => $user->getCurrentPlan(),
                'status' => $user->subscribed('default') ? 'active' : 'inactive',
                'trial_ends_at' => $user->trial_ends_at?->toIso8601String(),
                'ends_at' => $user->subscription('default')?->ends_at?->toIso8601String(),
            ],
            'alerts' => $this->getActiveAlerts($user),
        ];
    }

    /**
     * Get fraud check statistics for a period.
     */
    protected function getFraudCheckStats($user, string $period, string $groupBy): array
    {
        $startDate = $this->getStartDateForPeriod($period);

        $query = $user->fraudChecks()
            ->where('created_at', '>=', $startDate)
            ->select(
                DB::raw($this->getDateGroupExpression($groupBy).' as date'),
                DB::raw('COUNT(*) as total'),
                DB::raw('AVG(risk_score) as avg_risk_score'),
                DB::raw('SUM(CASE WHEN decision = \'block\' THEN 1 ELSE 0 END) as blocked')
            )
            ->groupBy('date')
            ->orderBy('date');

        $data = $query->get()->map(function ($item) {
            return [
                'date' => $item->date,
                'total' => (int) $item->total,
                'average_risk_score' => round($item->avg_risk_score, 2),
                'blocked' => (int) $item->blocked,
            ];
        });

        return [
            'period' => $period,
            'group_by' => $groupBy,
            'data' => $data,
        ];
    }

    /**
     * Get analytics for specified metrics.
     */
    protected function getAnalytics($user, $startDate, $endDate, array $metrics): array
    {
        $analytics = [];

        if (in_array('api_calls', $metrics)) {
            $analytics['api_calls'] = $this->getApiCallAnalytics($user, $startDate, $endDate);
        }

        if (in_array('fraud_checks', $metrics)) {
            $analytics['fraud_checks'] = $this->getFraudCheckAnalytics($user, $startDate, $endDate);
        }

        if (in_array('risk_scores', $metrics)) {
            $analytics['risk_scores'] = $this->getRiskScoreAnalytics($user, $startDate, $endDate);
        }

        if (in_array('response_times', $metrics)) {
            $analytics['response_times'] = $this->getResponseTimeAnalytics($user, $startDate, $endDate);
        }

        if (in_array('costs', $metrics)) {
            $analytics['costs'] = $this->getCostAnalytics($user, $startDate, $endDate);
        }

        return $analytics;
    }

    /**
     * Get recent activity.
     */
    protected function getRecentActivity($user, int $limit, string $type): array
    {
        $activity = [];

        if ($type === 'all' || $type === 'fraud_checks') {
            $fraudChecks = $user->fraudChecks()
                ->with('apiKey:id,name')
                ->orderBy('created_at', 'desc')
                ->limit($limit)
                ->get()
                ->map(function ($check) {
                    return [
                        'type' => 'fraud_check',
                        'id' => $check->id,
                        'risk_score' => $check->risk_score,
                        'decision' => $check->decision,
                        'api_key' => $check->apiKey?->name,
                        'timestamp' => $check->created_at->toIso8601String(),
                    ];
                });

            $activity = array_merge($activity, $fraudChecks->toArray());
        }

        if ($type === 'all' || $type === 'high_risk') {
            $highRiskChecks = $user->fraudChecks()
                ->where('risk_score', '>=', 80)
                ->orderBy('created_at', 'desc')
                ->limit($limit)
                ->get()
                ->map(function ($check) {
                    return [
                        'type' => 'high_risk',
                        'id' => $check->id,
                        'risk_score' => $check->risk_score,
                        'decision' => $check->decision,
                        'failed_checks' => array_keys($check->failed_checks ?? []),
                        'timestamp' => $check->created_at->toIso8601String(),
                    ];
                });

            $activity = array_merge($activity, $highRiskChecks->toArray());
        }

        // Sort by timestamp and limit
        usort($activity, function ($a, $b) {
            return strcmp($b['timestamp'], $a['timestamp']);
        });

        return array_slice($activity, 0, $limit);
    }

    /**
     * Get billing period for user.
     */
    protected function getBillingPeriod($user): array
    {
        if ($user->subscribed('default')) {
            $subscription = $user->subscription('default')->asStripeSubscription();

            return [
                Carbon::createFromTimestamp($subscription->current_period_start),
                Carbon::createFromTimestamp($subscription->current_period_end),
            ];
        }

        // Free tier - monthly reset
        return [
            $user->free_checks_reset_at ? $user->free_checks_reset_at->subMonth() : $user->created_at,
            $user->free_checks_reset_at ?? now(),
        ];
    }

    /**
     * Get start date for period.
     */
    protected function getStartDateForPeriod(string $period): Carbon
    {
        return match ($period) {
            'hour' => now()->subHour(),
            'day' => now()->subDay(),
            'week' => now()->subWeek(),
            'month' => now()->subMonth(),
            'year' => now()->subYear(),
            default => now()->subMonth(),
        };
    }

    /**
     * Get date grouping expression.
     */
    protected function getDateGroupExpression(string $groupBy): string
    {
        return match ($groupBy) {
            'hour' => "DATE_FORMAT(created_at, '%Y-%m-%d %H:00:00')",
            'day' => 'DATE(created_at)',
            'week' => 'DATE(DATE_SUB(created_at, INTERVAL DAYOFWEEK(created_at)-1 DAY))',
            'month' => "DATE_FORMAT(created_at, '%Y-%m-01')",
            default => 'DATE(created_at)',
        };
    }

    /**
     * Get active alerts for user.
     */
    protected function getActiveAlerts($user): array
    {
        $alerts = [];

        // Check if approaching rate limit
        $hourlyUsage = $user->apiUsage()->where('created_at', '>=', now()->startOfHour())->count();
        $rateLimit = $user->getRateLimit();

        if ($hourlyUsage > $rateLimit * 0.8) {
            $alerts[] = [
                'type' => 'rate_limit',
                'severity' => 'warning',
                'message' => 'Approaching rate limit ('.round(($hourlyUsage / $rateLimit) * 100).'% used)',
            ];
        }

        // Check if free tier is running out
        if (! $user->subscribed('default') && $user->free_checks_remaining < 20) {
            $alerts[] = [
                'type' => 'free_tier',
                'severity' => 'info',
                'message' => 'Only '.$user->free_checks_remaining.' free checks remaining',
            ];
        }

        // Check for recent high-risk detections
        $recentHighRisk = $user->fraudChecks()
            ->where('created_at', '>=', now()->subHour())
            ->where('risk_score', '>=', 80)
            ->count();

        if ($recentHighRisk > 5) {
            $alerts[] = [
                'type' => 'high_risk',
                'severity' => 'error',
                'message' => $recentHighRisk.' high-risk detections in the last hour',
            ];
        }

        return $alerts;
    }

    /**
     * Get API call analytics.
     */
    protected function getApiCallAnalytics($user, $startDate, $endDate): array
    {
        return $user->apiUsage()
            ->whereBetween('created_at', [$startDate, $endDate])
            ->selectRaw('
                DATE(created_at) as date,
                COUNT(*) as total,
                SUM(CASE WHEN response_code >= 200 AND response_code < 300 THEN 1 ELSE 0 END) as successful,
                SUM(CASE WHEN response_code >= 400 THEN 1 ELSE 0 END) as failed
            ')
            ->groupBy('date')
            ->orderBy('date')
            ->get()
            ->toArray();
    }

    /**
     * Get fraud check analytics.
     */
    protected function getFraudCheckAnalytics($user, $startDate, $endDate): array
    {
        return $user->fraudChecks()
            ->whereBetween('created_at', [$startDate, $endDate])
            ->selectRaw('
                DATE(created_at) as date,
                COUNT(*) as total,
                SUM(CASE WHEN decision = \'allow\' THEN 1 ELSE 0 END) as allowed,
                SUM(CASE WHEN decision = \'review\' THEN 1 ELSE 0 END) as review,
                SUM(CASE WHEN decision = \'block\' THEN 1 ELSE 0 END) as blocked
            ')
            ->groupBy('date')
            ->orderBy('date')
            ->get()
            ->toArray();
    }

    /**
     * Get risk score analytics.
     */
    protected function getRiskScoreAnalytics($user, $startDate, $endDate): array
    {
        return $user->fraudChecks()
            ->whereBetween('created_at', [$startDate, $endDate])
            ->selectRaw('
                DATE(created_at) as date,
                AVG(risk_score) as average,
                MIN(risk_score) as min,
                MAX(risk_score) as max,
                STDDEV(risk_score) as std_dev
            ')
            ->groupBy('date')
            ->orderBy('date')
            ->get()
            ->map(function ($item) {
                return [
                    'date' => $item->date,
                    'average' => round($item->average, 2),
                    'min' => (int) $item->min,
                    'max' => (int) $item->max,
                    'std_dev' => round($item->std_dev, 2),
                ];
            })
            ->toArray();
    }

    /**
     * Get response time analytics.
     */
    protected function getResponseTimeAnalytics($user, $startDate, $endDate): array
    {
        return $user->apiUsage()
            ->whereBetween('created_at', [$startDate, $endDate])
            ->selectRaw('
                DATE(created_at) as date,
                AVG(response_time_ms) as average,
                MIN(response_time_ms) as min,
                MAX(response_time_ms) as max,
                PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY response_time_ms) as p95
            ')
            ->groupBy('date')
            ->orderBy('date')
            ->get()
            ->map(function ($item) {
                return [
                    'date' => $item->date,
                    'average' => round($item->average, 2),
                    'min' => (int) $item->min,
                    'max' => (int) $item->max,
                    'p95' => round($item->p95, 2),
                ];
            })
            ->toArray();
    }

    /**
     * Get cost analytics.
     */
    protected function getCostAnalytics($user, $startDate, $endDate): array
    {
        return $user->apiUsage()
            ->whereBetween('created_at', [$startDate, $endDate])
            ->where('is_billable', true)
            ->selectRaw('
                DATE(created_at) as date,
                SUM(cost) as total_cost,
                COUNT(*) as billable_requests,
                SUM(CASE WHEN is_over_limit THEN cost ELSE 0 END) as overage_cost
            ')
            ->groupBy('date')
            ->orderBy('date')
            ->get()
            ->map(function ($item) {
                return [
                    'date' => $item->date,
                    'total_cost' => round($item->total_cost, 2),
                    'billable_requests' => (int) $item->billable_requests,
                    'overage_cost' => round($item->overage_cost, 2),
                ];
            })
            ->toArray();
    }
}
