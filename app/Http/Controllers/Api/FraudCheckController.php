<?php

namespace App\Http\Controllers\Api;

use App\Events\FraudCheckPerformedEvent;
use App\Http\Controllers\Controller;
use App\Http\Requests\FraudCheckRequest;
use App\Services\FraudDetection\FraudDetectionService;
use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\RateLimiter;

class FraudCheckController extends Controller
{
    protected FraudDetectionService $fraudService;

    public function __construct(FraudDetectionService $fraudService)
    {
        $this->fraudService = $fraudService;
    }

    /**
     * Perform fraud check
     *
     * @OA\Post(
     *     path="/api/v1/fraud-check",
     *     summary="Check fraud risk for provided data",
     *     tags={"Fraud Detection"},
     *     security={{"api_key": {}}},
     *
     *     @OA\RequestBody(
     *         required=true,
     *
     *         @OA\JsonContent(
     *
     *             @OA\Property(property="email", type="string", example="user@example.com"),
     *             @OA\Property(property="ip", type="string", example="192.168.1.1"),
     *             @OA\Property(property="credit_card", type="string", example="4111111111111111"),
     *             @OA\Property(property="phone", type="string", example="+1234567890"),
     *             @OA\Property(property="user_agent", type="string"),
     *             @OA\Property(property="domain", type="string", example="example.com"),
     *             @OA\Property(property="country", type="string", example="US"),
     *             @OA\Property(property="timezone", type="string", example="America/New_York")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Fraud check result",
     *
     *         @OA\JsonContent(
     *
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="data", type="object",
     *                 @OA\Property(property="risk_score", type="integer", example=25),
     *                 @OA\Property(property="decision", type="string", example="allow"),
     *                 @OA\Property(property="checks", type="object"),
     *                 @OA\Property(property="id", type="string"),
     *                 @OA\Property(property="processing_time_ms", type="integer")
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=429,
     *         description="Rate limit exceeded"
     *     )
     * )
     */
    public function check(FraudCheckRequest $request): JsonResponse
    {
        $apiKey = $request->apiKey;

        $user = $apiKey->user;

        // Check rate limit
        $rateLimitKey = "fraud-check:$apiKey->id";
        $maxAttempts = $apiKey->rate_limit;

        if (! RateLimiter::attempt($rateLimitKey, $maxAttempts, function () {}, 3600)) {
            // Check if user has billing enabled
            if (! $user->subscribed('default')) {
                return response()->json([
                    'success' => false,
                    'error' => 'Rate limit exceeded. Please upgrade your plan to continue.',
                    'upgrade_url' => config('app.url').'/billing',
                ], 429);
            }

            // Mark this request as billable
            $request->merge(['is_over_limit' => true]);
        }

        // Check free tier limits
        if (! $user->subscribed('default') && $user->free_checks_remaining <= 0) {
            return response()->json([
                'success' => false,
                'error' => 'Free tier limit reached. Please upgrade to continue.',
                'upgrade_url' => config('app.url').'/billing',
            ], 402);
        }

        try {
            // Prepare data for fraud check
            $data = $request->validated();
            $data['headers'] = $request->headers->all();
            $data['user_agent'] = $request->header('User-Agent');

            // Perform fraud check
            $result = $this->fraudService->check($data, $user, $apiKey);

            // Decrement free checks if not subscribed
            if (! $user->subscribed('default') && ! ($request->is_over_limit ?? false)) {
                $user->decrement('free_checks_remaining');
            }

            // Fire event for logging and webhooks
            event(new FraudCheckPerformedEvent($user, $apiKey, $result));

            // Format response
            return response()->json([
                'success' => true,
                'data' => [
                    'risk_score' => $result['risk_score'],
                    'decision' => $result['decision'],
                    'checks' => $this->formatChecks($result['checks']),
                    'id' => $result['id'],
                    'processing_time_ms' => $result['processing_time_ms'],
                ],
            ]);

        } catch (Exception $e) {
            return response()->json([
                'success' => false,
                'error' => 'An error occurred during fraud check',
                'message' => config('app.debug') ? $e->getMessage() : null,
            ], 500);
        }
    }

    /**
     * Get fraud check by ID
     */
    public function show(string $id): JsonResponse
    {
        $apiKey = request()->apiKey;

        $fraudCheck = $apiKey->user->fraudChecks()
            ->where('id', $id)
            ->first();

        if (! $fraudCheck) {
            return response()->json([
                'success' => false,
                'error' => 'Fraud check not found',
            ], 404);
        }

        return response()->json([
            'success' => true,
            'data' => [
                'id' => $fraudCheck->id,
                'risk_score' => $fraudCheck->risk_score,
                'decision' => $fraudCheck->decision,
                'checks' => $fraudCheck->check_results,
                'created_at' => $fraudCheck->created_at->toIso8601String(),
                'processing_time_ms' => $fraudCheck->processing_time_ms,
            ],
        ]);
    }

    /**
     * List recent fraud checks
     */
    public function index(): JsonResponse
    {
        $apiKey = request()->apiKey;

        $checks = $apiKey->user->fraudChecks()
            ->orderBy('created_at', 'desc')
            ->paginate(20);

        return response()->json([
            'success' => true,
            'data' => $checks->items(),
            'meta' => [
                'current_page' => $checks->currentPage(),
                'total_pages' => $checks->lastPage(),
                'total_items' => $checks->total(),
                'per_page' => $checks->perPage(),
            ],
        ]);
    }

    /**
     * Format checks for response
     */
    protected function formatChecks(array $checks): array
    {

        return array_map(function ($result) {
            return [
                'passed' => $result['passed'],
                'score' => $result['score'],
                'details' => $this->sanitizeDetails($result['details'] ?? []),
            ];
        }, $checks);
    }

    /**
     * Sanitize check details to remove sensitive information
     */
    protected function sanitizeDetails(array $details): array
    {
        // Remove any potentially sensitive data
        $sensitive = ['email', 'ip_address', 'credit_card', 'phone'];

        foreach ($sensitive as $key) {
            unset($details[$key]);
        }

        return $details;
    }
}
