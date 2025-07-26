<?php

namespace App\Http\Middleware;

use App\Models\ApiKey;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class ApiAuthenticationMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @return mixed
     */
    public function handle(Request $request, Closure $next, ?string $permission = null)
    {
        $apiKeyString = $this->extractApiKey($request);
        $apiSecret = $this->extractApiSecret($request);

        if (!$apiKeyString || !$apiSecret) {
            return response()->json([
                'success' => false,
                'error' => 'API key and secret are required',
                'message' => 'Please provide X-API-Key and X-API-Secret headers',
            ], 401);
        }

        // Get API key from cache or database
        $apiKey = $this->getApiKey($apiKeyString);

        if (!$apiKey) {
            return response()->json([
                'success' => false,
                'error' => 'Invalid API key',
            ], 401);
        }

        // Verify secret
        if (!$apiKey->verifySecret($apiSecret)) {
            return response()->json([
                'success' => false,
                'error' => 'Invalid API secret',
            ], 401);
        }

        // Check if API key is valid
        if (!$apiKey->isValid()) {
            $reason = !$apiKey->is_active ? 'inactive' : 'expired';
            return response()->json([
                'success' => false,
                'error' => "API key is {$reason}",
            ], 401);
        }

        // Check permission if specified
        if ($permission && !$apiKey->hasPermission($permission)) {
            return response()->json([
                'success' => false,
                'error' => 'Insufficient permissions',
                'required_permission' => $permission,
            ], 403);
        }

        // Load user relationship
        $apiKey->load('user');

        // Check if user account is active
        if (!$apiKey->user) {
            return response()->json([
                'success' => false,
                'error' => 'Associated user account not found',
            ], 401);
        }

        // Mark API key as used
        $apiKey->markAsUsed();

        // Add to request for use in controllers
        $request->merge(['apiKey' => $apiKey]);
        $request->setUserResolver(function () use ($apiKey) {
            return $apiKey->user;
        });

        return $next($request);
    }

    /**
     * Extract API key from request.
     */
    protected function extractApiKey(Request $request): ?string
    {
        // Check X-API-Key header
        $apiKey = $request->header('X-API-Key');

        if ($apiKey) {
            return $apiKey;
        }

        // Check Authorization header (Bearer token format)
        $authHeader = $request->header('Authorization');
        if ($authHeader && str_starts_with($authHeader, 'Bearer ')) {
            return substr($authHeader, 7);
        }

        // Check query parameter (less secure, for testing only)
        return $request->query('api_key');
    }

    /**
     * Extract API secret from request.
     */
    protected function extractApiSecret(Request $request): ?string
    {
        // Check X-API-Secret header
        $apiSecret = $request->header('X-API-Secret');

        if ($apiSecret) {
            return $apiSecret;
        }

        // Check query parameter (less secure, for testing only)
        return $request->query('api_secret');
    }

    /**
     * Get API key from cache or database.
     */
    protected function getApiKey(string $apiKeyString): ?ApiKey
    {
        return Cache::remember("api_key:{$apiKeyString}", 300, function () use ($apiKeyString) {
            return ApiKey::where('key', $apiKeyString)
                ->where('is_active', true)
                ->with('user')
                ->first();
        });
    }
}
