<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class WebhookService
{
    /**
     * Send webhook to specified URL.
     *
     * @throws \Exception
     */
    public function send(string $url, array $payload, ?string $secret = null): array
    {
        $headers = [
            'Content-Type' => 'application/json',
            'User-Agent' => 'FraudGuard-Webhook/1.0',
            'X-Webhook-Timestamp' => (string) time(),
        ];

        // Add signature if secret provided
        if ($secret) {
            $signature = $this->generateSignature($payload, $secret, $headers['X-Webhook-Timestamp']);
            $headers['X-Webhook-Signature'] = $signature;
        }

        try {
            $response = Http::withHeaders($headers)
                ->timeout(config('fraud-detection.webhooks.timeout', 10))
                ->retry(
                    config('fraud-detection.webhooks.retry_times', 3),
                    config('fraud-detection.webhooks.retry_delay', 100)
                )
                ->post($url, $payload);

            return [
                'success' => $response->successful(),
                'status_code' => $response->status(),
                'body' => $response->body(),
            ];

        } catch (\Illuminate\Http\Client\ConnectionException $e) {
            Log::error('Webhook connection failed', [
                'url' => $url,
                'error' => $e->getMessage(),
            ]);

            throw new \Exception('Failed to connect to webhook URL: '.$e->getMessage());
        } catch (\Exception $e) {
            Log::error('Webhook request failed', [
                'url' => $url,
                'error' => $e->getMessage(),
            ]);

            throw $e;
        }
    }

    /**
     * Generate webhook signature.
     */
    public function generateSignature(array $payload, string $secret, string $timestamp): string
    {
        $payloadString = json_encode($payload);
        $signatureBase = $timestamp.'.'.$payloadString;

        return 'sha256='.hash_hmac('sha256', $signatureBase, $secret);
    }

    /**
     * Verify webhook signature.
     */
    public function verifySignature(string $payload, string $signature, string $secret, string $timestamp): bool
    {
        // Check timestamp to prevent replay attacks
        $currentTime = time();
        $webhookTime = (int) $timestamp;

        if (abs($currentTime - $webhookTime) > 300) { // 5 minutes tolerance
            return false;
        }

        $signatureBase = $timestamp.'.'.$payload;
        $expectedSignature = 'sha256='.hash_hmac('sha256', $signatureBase, $secret);

        return hash_equals($expectedSignature, $signature);
    }

    /**
     * Test webhook endpoint.
     */
    public function test(string $url, ?string $secret = null): array
    {
        $testPayload = [
            'event' => 'test',
            'timestamp' => now()->toIso8601String(),
            'data' => [
                'message' => 'This is a test webhook from FraudGuard',
            ],
        ];

        try {
            return $this->send($url, $testPayload, $secret);
        } catch (\Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage(),
            ];
        }
    }
}
