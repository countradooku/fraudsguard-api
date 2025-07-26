<?php

namespace App\Http\Middleware;

use App\Models\ApiUsage;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;

class LogApiUsageMiddleware
{
    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): mixed
    {
        $startTime = microtime(true);

        // Process the request
        $response = $next($request);

        // Calculate response time
        $responseTime = (int) ((microtime(true) - $startTime) * 1000);

        // Log the API usage
        $this->logUsage($request, $response, $responseTime);

        return $response;
    }

    /**
     * Log API usage to database
     */
    protected function logUsage(Request $request, $response, int $responseTime): void
    {
        // Skip logging for certain endpoints
        $skipEndpoints = ['/api/health', '/api/v1/health'];
        if (in_array($request->path(), $skipEndpoints)) {
            return;
        }

        try {
            $user = $request->user ?? null;
            $apiKey = $request->apiKey ?? null;

            if (! $user) {
                return;
            }

            // Determine if request is billable
            $isBillable = $this->isBillable($request, $response);
            $isOverLimit = $request->is_over_limit ?? false;

            // Calculate cost if applicable
            $cost = 0;
            if ($isOverLimit && $isBillable) {
                $cost = $this->calculateCost($user);
            }

            // Create usage record
            ApiUsage::create([
                'user_id' => $user->id,
                'api_key_id' => $apiKey?->id,
                'endpoint' => $request->path(),
                'method' => $request->method(),
                'response_code' => $response->status(),
                'response_time_ms' => $responseTime,
                'is_billable' => $isBillable,
                'is_over_limit' => $isOverLimit,
                'cost' => $cost,
                'ip_address' => $request->ip(),
                'request_headers' => $this->sanitizeHeaders($request->headers->all()),
                'request_body' => $this->shouldLogBody($request) ? $this->sanitizeBody($request->all()) : null,
            ]);

        } catch (\Exception $e) {
            // Don't let logging errors break the API
            \Log::error('Failed to log API usage', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);
        }
    }

    /**
     * Determine if request is billable
     */
    protected function isBillable(Request $request, $response): bool
    {
        // Only successful fraud checks are billable
        if (! str_contains($request->path(), 'fraud/check')) {
            return false;
        }

        // Only POST requests to fraud check endpoint
        if ($request->method() !== 'POST') {
            return false;
        }

        // Only successful responses
        if ($response->status() < 200 || $response->status() >= 300) {
            return false;
        }

        return true;
    }

    /**
     * Calculate cost for overage request
     */
    protected function calculateCost($user): float
    {
        $plan = $user->getCurrentPlan();

        $overagePricing = Config::get('fraud-detection.overage_pricing', [
            'basic' => 0.01,
            'pro' => 0.005,
            'enterprise' => 0.001,
        ]);

        return $overagePricing[$plan] ?? 0;
    }

    /**
     * Sanitize headers for storage
     */
    protected function sanitizeHeaders(array $headers): array
    {
        $sanitized = [];
        $allowedHeaders = [
            'user-agent', 'accept', 'content-type', 'origin', 'referer',
            'x-requested-with', 'x-forwarded-for', 'x-real-ip',
        ];

        foreach ($headers as $key => $values) {
            $key = strtolower($key);
            if (in_array($key, $allowedHeaders)) {
                $sanitized[$key] = is_array($values) ? $values[0] : $values;
            }
        }

        return $sanitized;
    }

    /**
     * Determine if request body should be logged
     */
    protected function shouldLogBody(Request $request): bool
    {
        // Only log fraud check requests
        return str_contains($request->path(), 'fraud/check') &&
            $request->method() === 'POST';
    }

    /**
     * Sanitize request body for storage
     */
    protected function sanitizeBody(array $body): array
    {
        $sensitive = ['credit_card', 'password', 'secret'];

        foreach ($sensitive as $field) {
            if (isset($body[$field])) {
                $body[$field] = '***REDACTED***';
            }
        }

        return $body;
    }
}
