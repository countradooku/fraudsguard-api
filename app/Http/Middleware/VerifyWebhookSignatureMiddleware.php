<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Stripe\Exception\SignatureVerificationException;
use Stripe\Webhook;

class VerifyWebhookSignatureMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        $signature = $request->header('Stripe-Signature');
        $secret = Config::get('cashier.webhook.secret');

        if (! $signature || ! $secret) {
            return response()->json(['error' => 'Missing webhook signature'], 400);
        }

        try {
            Webhook::constructEvent(
                $request->getContent(),
                $signature,
                $secret
            );
        } catch (SignatureVerificationException $e) {
            return response()->json(['error' => 'Invalid signature'], 400);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Webhook error'], 400);
        }

        return $next($request);
    }
}
