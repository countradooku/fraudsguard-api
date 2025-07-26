<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Laravel\Cashier\Exceptions\IncompletePayment;

class BillingController extends Controller
{
    /**
     * Get current subscription information.
     */
    public function subscription(Request $request): JsonResponse
    {
        $user = $request->user();

        $subscription = $user->subscription('default');

        if (! $subscription) {
            return response()->json([
                'success' => true,
                'data' => [
                    'status' => 'inactive',
                    'plan' => 'free',
                    'limits' => [
                        'monthly_requests' => config('fraud-detection.free_tier_limit', 100),
                        'rate_limit' => config('fraud-detection.rate_limits.free', 100),
                    ],
                    'usage' => [
                        'current' => $user->getCurrentBillingPeriodUsage(),
                        'remaining' => $user->free_checks_remaining,
                        'reset_date' => $user->free_checks_reset_at?->toIso8601String(),
                    ],
                ],
            ]);
        }

        // Get current plan details
        $planDetails = $this->getPlanDetails($subscription->stripe_price);

        return response()->json([
            'success' => true,
            'data' => [
                'status' => $subscription->stripe_status,
                'plan' => $planDetails['name'],
                'price' => $planDetails['price'],
                'limits' => $planDetails['limits'],
                'current_period_start' => $subscription->asStripeSubscription()->current_period_start,
                'current_period_end' => $subscription->asStripeSubscription()->current_period_end,
                'cancel_at_period_end' => $subscription->cancelled(),
                'ends_at' => $subscription->ends_at?->toIso8601String(),
                'trial_ends_at' => $subscription->trial_ends_at?->toIso8601String(),
                'usage' => [
                    'current' => $user->getCurrentBillingPeriodUsage(),
                    'limit' => $planDetails['limits']['monthly_requests'],
                    'overage_cost' => $user->getOverageCharges(),
                ],
                'payment_method' => $user->defaultPaymentMethod() ? [
                    'brand' => $user->pm_type,
                    'last_four' => $user->pm_last_four,
                ] : null,
            ],
        ]);
    }

    /**
     * Subscribe to a plan.
     */
    public function subscribe(Request $request): JsonResponse
    {
        $request->validate([
            'plan' => 'required|string|in:basic,pro,enterprise',
            'payment_method' => 'required|string',
        ]);

        $user = $request->user();
        $plan = $request->plan;

        try {
            // Cancel existing subscription if any
            if ($user->subscribed('default')) {
                $user->subscription('default')->cancelNow();
            }

            // Get Stripe price ID from config
            $priceId = config("cashier.plans.{$plan}.price_id");

            if (! $priceId) {
                return response()->json([
                    'success' => false,
                    'error' => 'Invalid plan selected',
                ], 400);
            }

            // Create new subscription
            $subscription = $user->newSubscription('default', $priceId);

            // Add trial if eligible
            if ($user->hasNeverSubscribed()) {
                $subscription->trialDays(14);
            }

            $subscription->create($request->payment_method);

            return response()->json([
                'success' => true,
                'message' => 'Successfully subscribed to '.ucfirst($plan).' plan',
                'data' => [
                    'plan' => $plan,
                    'status' => 'active',
                    'trial_ends_at' => $user->subscription('default')->trial_ends_at?->toIso8601String(),
                ],
            ]);

        } catch (IncompletePayment $e) {
            return response()->json([
                'success' => false,
                'error' => 'Payment requires additional confirmation',
                'payment_intent' => $e->payment->asStripePaymentIntent()->client_secret,
            ], 402);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'error' => 'Subscription failed: '.$e->getMessage(),
            ], 400);
        }
    }

    /**
     * Cancel subscription.
     */
    public function cancel(Request $request): JsonResponse
    {
        $user = $request->user();

        if (! $user->subscribed('default')) {
            return response()->json([
                'success' => false,
                'error' => 'No active subscription found',
            ], 400);
        }

        try {
            $user->subscription('default')->cancel();

            return response()->json([
                'success' => true,
                'message' => 'Subscription will be cancelled at the end of the billing period',
                'data' => [
                    'ends_at' => $user->subscription('default')->ends_at->toIso8601String(),
                ],
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'error' => 'Failed to cancel subscription: '.$e->getMessage(),
            ], 400);
        }
    }

    /**
     * Resume cancelled subscription.
     */
    public function resume(Request $request): JsonResponse
    {
        $user = $request->user();

        if (! $user->subscription('default') || ! $user->subscription('default')->cancelled()) {
            return response()->json([
                'success' => false,
                'error' => 'No cancelled subscription found',
            ], 400);
        }

        try {
            $user->subscription('default')->resume();

            return response()->json([
                'success' => true,
                'message' => 'Subscription resumed successfully',
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'error' => 'Failed to resume subscription: '.$e->getMessage(),
            ], 400);
        }
    }

    /**
     * Get invoices.
     */
    public function invoices(Request $request): JsonResponse
    {
        $user = $request->user();

        try {
            $invoices = $user->invoices()->map(function ($invoice) {
                return [
                    'id' => $invoice->id,
                    'date' => $invoice->date()->toIso8601String(),
                    'total' => $invoice->total(),
                    'status' => $invoice->status,
                    'invoice_pdf' => $invoice->invoice_pdf,
                    'hosted_invoice_url' => $invoice->hosted_invoice_url,
                ];
            });

            return response()->json([
                'success' => true,
                'data' => $invoices,
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'error' => 'Failed to retrieve invoices',
            ], 400);
        }
    }

    /**
     * Download invoice.
     */
    public function downloadInvoice(Request $request, string $invoiceId)
    {
        $user = $request->user();

        try {
            return $user->downloadInvoice($invoiceId, [
                'vendor' => config('app.name'),
                'product' => 'Fraud Detection Service',
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'error' => 'Invoice not found',
            ], 404);
        }
    }

    /**
     * Update payment method.
     */
    public function updatePaymentMethod(Request $request): JsonResponse
    {
        $request->validate([
            'payment_method' => 'required|string',
        ]);

        $user = $request->user();

        try {
            $user->updateDefaultPaymentMethod($request->payment_method);

            return response()->json([
                'success' => true,
                'message' => 'Payment method updated successfully',
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'error' => 'Failed to update payment method: '.$e->getMessage(),
            ], 400);
        }
    }

    /**
     * Get plan details from price ID.
     */
    protected function getPlanDetails(string $priceId): array
    {
        $plans = [
            config('cashier.plans.basic.price_id') => [
                'name' => 'basic',
                'price' => 29,
                'limits' => [
                    'monthly_requests' => 10000,
                    'rate_limit' => config('fraud-detection.rate_limits.basic', 1000),
                ],
            ],
            config('cashier.plans.pro.price_id') => [
                'name' => 'pro',
                'price' => 99,
                'limits' => [
                    'monthly_requests' => 100000,
                    'rate_limit' => config('fraud-detection.rate_limits.pro', 10000),
                ],
            ],
            config('cashier.plans.enterprise.price_id') => [
                'name' => 'enterprise',
                'price' => 299,
                'limits' => [
                    'monthly_requests' => 1000000,
                    'rate_limit' => config('fraud-detection.rate_limits.enterprise', 100000),
                ],
            ],
        ];

        return $plans[$priceId] ?? [
            'name' => 'unknown',
            'price' => 0,
            'limits' => [
                'monthly_requests' => 0,
                'rate_limit' => 0,
            ],
        ];
    }
}
