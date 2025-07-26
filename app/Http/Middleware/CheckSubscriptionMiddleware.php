<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class CheckSubscriptionMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @return mixed
     */
    public function handle(Request $request, Closure $next, ?string $plan = null)
    {
        $user = $request->user();

        if (! $user) {
            return response()->json([
                'success' => false,
                'error' => 'Authentication required',
            ], 401);
        }

        // Check if user has any active subscription
        if ($plan === null) {
            if (! $user->subscribed('default')) {
                return response()->json([
                    'success' => false,
                    'error' => 'Active subscription required',
                    'message' => 'Please subscribe to access this feature',
                    'upgrade_url' => config('app.url').'/billing',
                ], 402);
            }
        } else {
            // Check for specific plan
            $currentPlan = $user->getCurrentPlan();
            $allowedPlans = explode(',', $plan);

            if (! in_array($currentPlan, $allowedPlans)) {
                return response()->json([
                    'success' => false,
                    'error' => 'Upgrade required',
                    'message' => 'This feature requires '.implode(' or ', $allowedPlans).' plan',
                    'current_plan' => $currentPlan,
                    'required_plans' => $allowedPlans,
                    'upgrade_url' => config('app.url').'/billing',
                ], 402);
            }
        }

        // Check if subscription is active (not cancelled or on grace period)
        $subscription = $user->subscription('default');
        if ($subscription && $subscription->canceled() && $subscription->onGracePeriod()) {
            // Add warning header
            $response = $next($request);
            $response->header('X-Subscription-Warning', 'Subscription ending on '.$subscription->ends_at->toDateString());

            return $response;
        }

        return $next($request);
    }
}
