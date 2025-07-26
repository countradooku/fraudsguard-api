<?php

namespace App\Http\Controllers\Api;

use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Log;
use Laravel\Cashier\Http\Controllers\WebhookController as CashierController;

class WebhookController extends CashierController
{
    /**
     * Handle customer subscription created.
     */
    protected function handleCustomerSubscriptionCreated(array $payload): JsonResponse
    {
        $user = $this->getUserByStripeId($payload['data']['object']['customer']);

        if ($user) {
            Log::info('Subscription created for user', [
                'user_id' => $user->id,
                'subscription_id' => $payload['data']['object']['id'],
            ]);

            // Update user's rate limit based on new plan
            $this->updateUserRateLimit($user);

            // Send welcome email for new subscription
            // $user->notify(new SubscriptionStarted());
        }

        return response()->json(['status' => 'success']);
    }

    /**
     * Handle customer subscription updated.
     */
    protected function handleCustomerSubscriptionUpdated(array $payload): JsonResponse
    {
        $user = $this->getUserByStripeId($payload['data']['object']['customer']);

        if ($user) {
            Log::info('Subscription updated for user', [
                'user_id' => $user->id,
                'subscription_id' => $payload['data']['object']['id'],
            ]);

            // Update user's rate limit based on new plan
            $this->updateUserRateLimit($user);
        }

        return response()->json(['status' => 'success']);
    }

    /**
     * Handle customer subscription deleted.
     */
    protected function handleCustomerSubscriptionDeleted(array $payload): JsonResponse
    {
        $user = $this->getUserByStripeId($payload['data']['object']['customer']);

        if ($user) {
            Log::info('Subscription cancelled for user', [
                'user_id' => $user->id,
                'subscription_id' => $payload['data']['object']['id'],
            ]);

            // Reset to free tier limits
            $user->update([
                'free_checks_remaining' => config('fraud-detection.free_tier_limit', 100),
                'free_checks_reset_at' => now()->addMonth(),
            ]);

            // Update API keys to free tier rate limit
            $user->apiKeys()->update([
                'rate_limit' => config('fraud-detection.rate_limits.free', 100),
            ]);

            // Send cancellation email
            // $user->notify(new SubscriptionCancelled());
        }

        return response()->json(['status' => 'success']);
    }

    /**
     * Handle invoice payment succeeded.
     */
    protected function handleInvoicePaymentSucceeded(array $payload): JsonResponse
    {
        $user = $this->getUserByStripeId($payload['data']['object']['customer']);

        if ($user) {
            Log::info('Payment succeeded for user', [
                'user_id' => $user->id,
                'amount' => $payload['data']['object']['amount_paid'],
                'invoice_id' => $payload['data']['object']['id'],
            ]);

            // Record successful payment
            // You might want to store this in a payments table
        }

        return response()->json(['status' => 'success']);
    }

    /**
     * Handle invoice payment failed.
     */
    protected function handleInvoicePaymentFailed(array $payload): JsonResponse
    {
        $user = $this->getUserByStripeId($payload['data']['object']['customer']);

        if ($user) {
            Log::warning('Payment failed for user', [
                'user_id' => $user->id,
                'invoice_id' => $payload['data']['object']['id'],
            ]);

            // Send payment failure notification
            // $user->notify(new PaymentFailed());
        }

        return response()->json(['status' => 'success']);
    }

    /**
     * Handle checkout session completed.
     */
    protected function handleCheckoutSessionCompleted(array $payload): JsonResponse
    {
        $session = $payload['data']['object'];

        if ($session['mode'] === 'subscription') {
            $user = User::where('stripe_id', $session['customer'])->first();

            if ($user) {
                Log::info('Checkout completed for user', [
                    'user_id' => $user->id,
                    'session_id' => $session['id'],
                ]);
            }
        }

        return response()->json(['status' => 'success']);
    }

    /**
     * Handle customer updated.
     */
    protected function handleCustomerUpdated(array $payload): JsonResponse
    {
        $user = $this->getUserByStripeId($payload['data']['object']['id']);

        if ($user) {
            // Update stored payment method info if changed
            $defaultSource = $payload['data']['object']['default_source'] ?? null;

            if ($defaultSource && isset($payload['data']['object']['sources']['data'])) {
                foreach ($payload['data']['object']['sources']['data'] as $source) {
                    if ($source['id'] === $defaultSource) {
                        $user->update([
                            'pm_type' => $source['brand'] ?? null,
                            'pm_last_four' => $source['last4'] ?? null,
                        ]);
                        break;
                    }
                }
            }
        }

        return response()->json(['status' => 'success']);
    }

    /**
     * Update user's rate limit based on their subscription.
     */
    protected function updateUserRateLimit(User $user): void
    {
        $rateLimit = $user->getRateLimit();

        // Update all active API keys
        $user->apiKeys()
            ->where('is_active', true)
            ->update(['rate_limit' => $rateLimit]);
    }

    /**
     * Handle Stripe webhook verification errors.
     */
    protected function handleWebhookVerificationError(\Exception $e): JsonResponse
    {
        Log::error('Webhook verification failed', [
            'error' => $e->getMessage(),
        ]);

        return response()->json([
            'error' => 'Webhook verification failed',
        ], 400);
    }
}
