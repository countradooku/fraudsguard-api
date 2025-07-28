<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\ApiKey;
use Cache;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class ApiKeyController extends Controller
{
    /**
     * Display a listing of the user's API keys.
     */
    public function index(Request $request): JsonResponse
    {
        $apiKeys = $request->user()->apiKeys()
            ->select('id', 'name', 'key', 'permissions', 'rate_limit', 'last_used_at', 'expires_at', 'is_active', 'created_at')
            ->orderBy('created_at', 'desc')
            ->get()
            ->map(function (ApiKey $key) {
                return [
                    'id' => $key->id,
                    'name' => $key->name,
                    'key' => $key->key,
                    'permissions' => $key->permissions,
                    'rate_limit' => $key->rate_limit,
                    'last_used_at' => $key->last_used_at?->toIso8601String(),
                    'expires_at' => $key->expires_at?->toIso8601String(),
                    'is_active' => $key->is_active,
                    'created_at' => $key->created_at->toIso8601String(),
                    'usage_stats' => $key->getUsageStats(),
                ];
            });

        return response()->json([
            'success' => true,
            'data' => $apiKeys,
        ]);
    }

    /**
     * Create a new API key.
     */
    public function create(Request $request): JsonResponse
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'permissions' => 'nullable|array',
            'permissions.*' => 'string|in:fraud_check,read_stats,manage_blacklist',
            'expires_at' => 'nullable|date|after:now',
        ]);

        $user = $request->user();

        // Check API key limit based on plan
        $keyLimit = match ($user->getCurrentPlan()) {
            'basic' => 5,
            'pro' => 20,
            'enterprise' => 100,
            default => 1,
        };

        if ($user->apiKeys()->where('is_active', true)->count() >= $keyLimit) {
            return response()->json([
                'success' => false,
                'error' => 'API key limit reached for your plan',
                'limit' => $keyLimit,
            ], 403);
        }

        // Generate new API key
        $result = ApiKey::generate($user, $request->name, [
            'permissions' => $request->permissions ?? [],
            'expires_at' => $request->expires_at,
        ]);

        return response()->json([
            'success' => true,
            'data' => [
                'id' => $result['model']->id,
                'name' => $result['model']->name,
                'key' => $result['key'],
                'secret' => $result['secret'],
                'created_at' => $result['model']->created_at->toIso8601String(),
            ],
            'message' => 'API key created successfully. Please store the secret securely as it will not be shown again.',
        ], 201);
    }

    /**
     * Display the specified API key.
     */
    public function show(Request $request, string $id): JsonResponse
    {
        $apiKey = $request->user()->apiKeys()->findOrFail($id);

        return response()->json([
            'success' => true,
            'data' => [
                'id' => $apiKey->id,
                'name' => $apiKey->name,
                'key' => $apiKey->key,
                'permissions' => $apiKey->permissions,
                'rate_limit' => $apiKey->rate_limit,
                'last_used_at' => $apiKey->last_used_at?->toIso8601String(),
                'expires_at' => $apiKey->expires_at?->toIso8601String(),
                'is_active' => $apiKey->is_active,
                'created_at' => $apiKey->created_at->toIso8601String(),
                'usage_stats' => [
                    'day' => $apiKey->getUsageStats('day'),
                    'week' => $apiKey->getUsageStats('week'),
                    'month' => $apiKey->getUsageStats(),
                ],
            ],
        ]);
    }

    /**
     * Update the specified API key.
     */
    public function update(Request $request, string $id): JsonResponse
    {
        $request->validate([
            'name' => 'sometimes|string|max:255',
            'permissions' => 'sometimes|array',
            'permissions.*' => 'string|in:fraud_check,read_stats,manage_blacklist',
            'is_active' => 'sometimes|boolean',
            'expires_at' => 'sometimes|nullable|date|after:now',
        ]);

        $apiKey = $request->user()->apiKeys()->findOrFail($id);

        $apiKey->update($request->only(['name', 'permissions', 'is_active', 'expires_at']));

        return response()->json([
            'success' => true,
            'data' => [
                'id' => $apiKey->id,
                'name' => $apiKey->name,
                'key' => $apiKey->key,
                'permissions' => $apiKey->permissions,
                'is_active' => $apiKey->is_active,
                'expires_at' => $apiKey->expires_at?->toIso8601String(),
                'updated_at' => $apiKey->updated_at->toIso8601String(),
            ],
            'message' => 'API key updated successfully',
        ]);
    }

    /**
     * Delete the specified API key.
     */
    public function destroy(Request $request, string $id): JsonResponse
    {
        $apiKey = $request->user()->apiKeys()->findOrFail($id);

        // Soft delete by deactivating
        $apiKey->revoke();

        return response()->json([
            'success' => true,
            'message' => 'API key revoked successfully',
        ]);
    }

    /**
     * Regenerate the secret for an API key.
     */
    public function regenerate(Request $request, string $id): JsonResponse
    {
        $apiKey = $request->user()->apiKeys()->findOrFail($id);

        // Generate new secret
        $newSecret = 'fds_'.Str::random(48);
        $apiKey->update([
            'secret_hash' => Hash::make($newSecret),
        ]);

        // Clear any cached data for this key
        Cache::forget("api_key:$apiKey->key");

        return response()->json([
            'success' => true,
            'data' => [
                'id' => $apiKey->id,
                'name' => $apiKey->name,
                'key' => $apiKey->key,
                'secret' => $newSecret,
            ],
            'message' => 'API secret regenerated successfully. Please store the new secret securely.',
        ]);
    }
}
