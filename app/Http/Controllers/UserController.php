<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rules\Password;

class UserController extends Controller
{
    /**
     * Get the authenticated user.
     */
    public function show(Request $request): JsonResponse
    {
        $user = $request->user();

        return response()->json([
            'success' => true,
            'data' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'email_verified_at' => $user->email_verified_at?->toIso8601String(),
                'company_name' => $user->company_name,
                'created_at' => $user->created_at->toIso8601String(),
                'subscription' => [
                    'plan' => $user->getCurrentPlan(),
                    'status' => $user->subscribed('default') ? 'active' : 'inactive',
                    'trial_ends_at' => $user->trial_ends_at?->toIso8601String(),
                ],
                'usage' => [
                    'current_period' => $user->getCurrentBillingPeriodUsage(),
                    'rate_limit' => $user->getRateLimit(),
                    'free_checks_remaining' => $user->free_checks_remaining,
                ],
                'stats' => $user->getFraudCheckStats(),
            ],
        ]);
    }

    /**
     * Update the authenticated user's profile.
     */
    public function update(Request $request): JsonResponse
    {
        $request->validate([
            'name' => 'sometimes|string|max:255',
            'company_name' => 'sometimes|nullable|string|max:255',
            'email' => 'sometimes|string|email|max:255|unique:users,email,'.$request->user()->id,
        ]);

        $user = $request->user();
        $user->update($request->only(['name', 'company_name', 'email']));

        // If email was changed, mark as unverified
        if ($request->has('email') && $request->email !== $user->email) {
            $user->update(['email_verified_at' => null]);
            $user->sendEmailVerificationNotification();
        }

        return response()->json([
            'success' => true,
            'message' => 'Profile updated successfully',
            'data' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'company_name' => $user->company_name,
            ],
        ]);
    }

    /**
     * Update the user's password.
     */
    public function updatePassword(Request $request): JsonResponse
    {
        $request->validate([
            'current_password' => 'required|string',
            'password' => ['required', 'confirmed', Password::defaults()],
        ]);

        $user = $request->user();

        // Verify current password
        if (! Hash::check($request->current_password, $user->password)) {
            return response()->json([
                'success' => false,
                'errors' => [
                    'current_password' => ['The current password is incorrect'],
                ],
            ], 422);
        }

        // Update password
        $user->update([
            'password' => Hash::make($request->password),
        ]);

        // Revoke all tokens except current
        $currentToken = $request->user()->currentAccessToken();
        $request->user()->tokens()->where('id', '!=', $currentToken->id)->delete();

        return response()->json([
            'success' => true,
            'message' => 'Password updated successfully',
        ]);
    }

    /**
     * Delete the user's account.
     */
    public function destroy(Request $request): JsonResponse
    {
        $request->validate([
            'password' => 'required|string',
        ]);

        $user = $request->user();

        // Verify password
        if (! Hash::check($request->password, $user->password)) {
            return response()->json([
                'success' => false,
                'error' => 'Invalid password',
            ], 422);
        }

        // Cancel any active subscriptions
        if ($user->subscribed('default')) {
            $user->subscription('default')->cancelNow();
        }

        // Revoke all API keys
        $user->apiKeys()->update(['is_active' => false]);

        // Delete user data (consider soft deletes for compliance)
        $user->fraudChecks()->delete();
        $user->apiUsage()->delete();
        $user->apiKeys()->delete();

        // Delete the user
        $user->delete();

        return response()->json([
            'success' => true,
            'message' => 'Account deleted successfully',
        ]);
    }

    /**
     * Get user's fraud check statistics.
     */
    public function statistics(Request $request): JsonResponse
    {
        $request->validate([
            'period' => 'string|in:day,week,month,year,all',
        ]);

        $user = $request->user();
        $period = $request->input('period', 'month');

        $query = $user->fraudChecks();

        // Apply period filter
        switch ($period) {
            case 'day':
                $query->where('created_at', '>=', now()->startOfDay());
                break;
            case 'week':
                $query->where('created_at', '>=', now()->startOfWeek());
                break;
            case 'month':
                $query->where('created_at', '>=', now()->startOfMonth());
                break;
            case 'year':
                $query->where('created_at', '>=', now()->startOfYear());
                break;
        }

        $stats = $query->selectRaw('
            COUNT(*) as total_checks,
            AVG(risk_score) as avg_risk_score,
            MAX(risk_score) as max_risk_score,
            MIN(risk_score) as min_risk_score,
            SUM(CASE WHEN decision = \'allow\' THEN 1 ELSE 0 END) as allowed,
            SUM(CASE WHEN decision = \'review\' THEN 1 ELSE 0 END) as review,
            SUM(CASE WHEN decision = \'block\' THEN 1 ELSE 0 END) as blocked,
            AVG(processing_time_ms) as avg_processing_time
        ')->first();

        // Get check type distribution
        $checkTypes = $query->selectRaw('
            SUM(CASE WHEN email_hash IS NOT NULL THEN 1 ELSE 0 END) as email_checks,
            SUM(CASE WHEN ip_hash IS NOT NULL THEN 1 ELSE 0 END) as ip_checks,
            SUM(CASE WHEN credit_card_hash IS NOT NULL THEN 1 ELSE 0 END) as credit_card_checks,
            SUM(CASE WHEN phone_hash IS NOT NULL THEN 1 ELSE 0 END) as phone_checks
        ')->first();

        return response()->json([
            'success' => true,
            'data' => [
                'period' => $period,
                'summary' => [
                    'total_checks' => $stats->total_checks ?? 0,
                    'average_risk_score' => round($stats->avg_risk_score ?? 0, 2),
                    'max_risk_score' => $stats->max_risk_score ?? 0,
                    'min_risk_score' => $stats->min_risk_score ?? 0,
                    'decisions' => [
                        'allowed' => $stats->allowed ?? 0,
                        'review' => $stats->review ?? 0,
                        'blocked' => $stats->blocked ?? 0,
                    ],
                    'average_processing_time' => round($stats->avg_processing_time ?? 0, 2),
                ],
                'check_types' => [
                    'email' => $checkTypes->email_checks ?? 0,
                    'ip' => $checkTypes->ip_checks ?? 0,
                    'credit_card' => $checkTypes->credit_card_checks ?? 0,
                    'phone' => $checkTypes->phone_checks ?? 0,
                ],
            ],
        ]);
    }
}
