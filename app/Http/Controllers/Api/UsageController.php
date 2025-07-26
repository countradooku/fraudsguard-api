<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Carbon\Carbon;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class UsageController extends Controller
{
    /**
     * Get usage summary.
     */
    public function index(Request $request): JsonResponse
    {
        $user = $request->user ?? $request->user();

        // Get current billing period usage
        $currentUsage = $user->getCurrentBillingPeriodUsage();

        // Get rate limit
        $rateLimit = $user->getRateLimit();

        // Get usage by endpoint
        $endpointUsage = $this->getEndpointUsage($user);

        // Get recent API calls
        $recentCalls = $user->apiUsage()
            ->latest()
            ->limit(10)
            ->get(['endpoint', 'method', 'response_code', 'response_time_ms', 'created_at']);

        return response()->json([
            'success' => true,
            'data' => [
                'current_period' => [
                    'usage' => $currentUsage,
                    'limit' => $rateLimit,
                    'percentage' => $rateLimit > 0 ? round(($currentUsage / $rateLimit) * 100, 2) : 0,
                ],
                'plan' => $user->getCurrentPlan(),
                'overage_charges' => $user->getOverageCharges(),
                'endpoint_usage' => $endpointUsage,
                'recent_calls' => $recentCalls,
            ],
        ]);
    }

    /**
     * Get daily usage statistics.
     */
    public function daily(Request $request): JsonResponse
    {
        $request->validate([
            'days' => 'integer|min:1|max:90',
            'timezone' => 'string|timezone',
        ]);

        $user = $request->user ?? $request->user();
        $days = $request->input('days', 30);
        $timezone = $request->input('timezone', 'UTC');

        $startDate = Carbon::now($timezone)->subDays($days)->startOfDay();

        $usage = $user->apiUsage()
            ->select(
                DB::raw("DATE(created_at AT TIME ZONE '$timezone') as date"),
                DB::raw('COUNT(*) as total_requests'),
                DB::raw('SUM(CASE WHEN response_code >= 200 AND response_code < 300 THEN 1 ELSE 0 END) as successful_requests'),
                DB::raw('SUM(CASE WHEN response_code >= 400 THEN 1 ELSE 0 END) as failed_requests'),
                DB::raw('SUM(CASE WHEN is_billable THEN 1 ELSE 0 END) as billable_requests'),
                DB::raw('AVG(response_time_ms) as avg_response_time'),
                DB::raw('SUM(cost) as daily_cost')
            )
            ->where('created_at', '>=', $startDate)
            ->groupBy('date')
            ->orderBy('date', 'desc')
            ->get()
            ->map(function ($day) {
                return [
                    'date' => $day->date,
                    'total_requests' => (int) $day->total_requests,
                    'successful_requests' => (int) $day->successful_requests,
                    'failed_requests' => (int) $day->failed_requests,
                    'billable_requests' => (int) $day->billable_requests,
                    'avg_response_time' => round($day->avg_response_time, 2),
                    'daily_cost' => round($day->daily_cost, 2),
                    'success_rate' => $day->total_requests > 0
                        ? round(($day->successful_requests / $day->total_requests) * 100, 2)
                        : 0,
                ];
            });

        // Fill in missing dates with zeros
        $allDates = collect();
        $currentDate = Carbon::now($timezone)->startOfDay();
        for ($i = 0; $i < $days; $i++) {
            $date = $currentDate->copy()->subDays($i)->format('Y-m-d');
            $existingData = $usage->firstWhere('date', $date);

            if ($existingData) {
                $allDates->push($existingData);
            } else {
                $allDates->push([
                    'date' => $date,
                    'total_requests' => 0,
                    'successful_requests' => 0,
                    'failed_requests' => 0,
                    'billable_requests' => 0,
                    'avg_response_time' => 0,
                    'daily_cost' => 0,
                    'success_rate' => 0,
                ]);
            }
        }

        return response()->json([
            'success' => true,
            'data' => $allDates->sortBy('date')->values(),
            'summary' => [
                'total_requests' => $usage->sum('total_requests'),
                'total_cost' => round($usage->sum('daily_cost'), 2),
                'average_daily_requests' => round($usage->avg('total_requests'), 2),
                'overall_success_rate' => $usage->sum('total_requests') > 0
                    ? round(($usage->sum('successful_requests') / $usage->sum('total_requests')) * 100, 2)
                    : 0,
            ],
        ]);
    }

    /**
     * Get monthly usage statistics.
     */
    public function monthly(Request $request): JsonResponse
    {
        $request->validate([
            'months' => 'integer|min:1|max:12',
        ]);

        $user = $request->user ?? $request->user();
        $months = $request->input('months', 6);

        $startDate = Carbon::now()->subMonths($months)->startOfMonth();

        $usage = $user->apiUsage()
            ->select(
                DB::raw("DATE_TRUNC('month', created_at) as month"),
                DB::raw('COUNT(*) as total_requests'),
                DB::raw('SUM(CASE WHEN response_code >= 200 AND response_code < 300 THEN 1 ELSE 0 END) as successful_requests'),
                DB::raw('SUM(CASE WHEN response_code >= 400 THEN 1 ELSE 0 END) as failed_requests'),
                DB::raw('SUM(CASE WHEN is_billable THEN 1 ELSE 0 END) as billable_requests'),
                DB::raw('SUM(CASE WHEN is_over_limit THEN 1 ELSE 0 END) as overage_requests'),
                DB::raw('AVG(response_time_ms) as avg_response_time'),
                DB::raw('SUM(cost) as monthly_cost')
            )
            ->where('created_at', '>=', $startDate)
            ->groupBy('month')
            ->orderBy('month', 'desc')
            ->get()
            ->map(function ($month) {
                return [
                    'month' => Carbon::parse($month->month)->format('Y-m'),
                    'total_requests' => (int) $month->total_requests,
                    'successful_requests' => (int) $month->successful_requests,
                    'failed_requests' => (int) $month->failed_requests,
                    'billable_requests' => (int) $month->billable_requests,
                    'overage_requests' => (int) $month->overage_requests,
                    'avg_response_time' => round($month->avg_response_time, 2),
                    'monthly_cost' => round($month->monthly_cost, 2),
                    'success_rate' => $month->total_requests > 0
                        ? round(($month->successful_requests / $month->total_requests) * 100, 2)
                        : 0,
                ];
            });

        // Calculate growth rates
        $growth = [];
        $sortedUsage = $usage->sortBy('month')->values();
        for ($i = 1; $i < $sortedUsage->count(); $i++) {
            $current = $sortedUsage[$i];
            $previous = $sortedUsage[$i - 1];

            if ($previous['total_requests'] > 0) {
                $growth[$current['month']] = round(
                    (($current['total_requests'] - $previous['total_requests']) / $previous['total_requests']) * 100,
                    2
                );
            }
        }

        return response()->json([
            'success' => true,
            'data' => $usage,
            'growth_rates' => $growth,
            'summary' => [
                'total_requests' => $usage->sum('total_requests'),
                'total_cost' => round($usage->sum('monthly_cost'), 2),
                'average_monthly_requests' => round($usage->avg('total_requests'), 2),
                'average_monthly_cost' => round($usage->avg('monthly_cost'), 2),
            ],
        ]);
    }

    /**
     * Get usage by endpoint.
     */
    protected function getEndpointUsage($user): array
    {
        return $user->apiUsage()
            ->select('endpoint', DB::raw('COUNT(*) as count'))
            ->where('created_at', '>=', Carbon::now()->startOfMonth())
            ->groupBy('endpoint')
            ->orderBy('count', 'desc')
            ->limit(10)
            ->pluck('count', 'endpoint')
            ->toArray();
    }
}
