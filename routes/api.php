<?php

use App\Http\Controllers\Api\ApiKeyController;
use App\Http\Controllers\Api\FraudCheckController;
use App\Http\Controllers\Api\UsageController;
use App\Http\Controllers\BillingController;
use App\Http\Controllers\UserController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
*/

// Stripe webhooks (no auth required)
Route::post('/stripe/webhook', [\App\Http\Controllers\Api\WebhookController::class, 'handleWebhook'])
    ->middleware('webhook.verify');

// Public endpoints
Route::prefix('v1')->group(function () {

    // Health check
    Route::get('/health', function () {
        return response()->json([
            'status' => 'healthy',
            'timestamp' => now()->toIso8601String(),
        ]);
    });

    // API endpoints requiring authentication
    Route::middleware(['guest'])->group(function () {

        // Fraud detection endpoints
        Route::prefix('fraud')->group(function () {
            Route::post('/check', [FraudCheckController::class, 'check']);
                //->middleware('throttle:fraud-check');
            Route::get('/check/{id}', [FraudCheckController::class, 'show']);
            Route::get('/checks', [FraudCheckController::class, 'index']);
        });

        // Usage statistics
        Route::prefix('usage')->group(function () {
            Route::get('/', [UsageController::class, 'index']);
            Route::get('/daily', [UsageController::class, 'daily']);
            Route::get('/monthly', [UsageController::class, 'monthly']);
        });
    });
});

// Authenticated user endpoints (using Sanctum)
Route::middleware('auth:sanctum')->group(function () {

    // User profile
    Route::prefix('user')->group(function () {
        Route::get('/', [UserController::class, 'show']);
        Route::put('/', [UserController::class, 'update']);
        Route::put('/password', [UserController::class, 'updatePassword']);
        Route::delete('/', [UserController::class, 'destroy']);
        Route::get('/statistics', [UserController::class, 'statistics']);
    });

    // API key management
    Route::prefix('api-keys')->group(function () {
        Route::get('/', [ApiKeyController::class, 'index']);
        Route::post('/', [ApiKeyController::class, 'create']);
        Route::get('/{id}', [ApiKeyController::class, 'show']);
        Route::put('/{id}', [ApiKeyController::class, 'update']);
        Route::delete('/{id}', [ApiKeyController::class, 'destroy']);
        Route::post('/{id}/regenerate', [ApiKeyController::class, 'regenerate']);
    });

    // Billing management
    Route::prefix('billing')->group(function () {
        Route::get('/subscription', [BillingController::class, 'subscription']);
        Route::post('/subscribe', [BillingController::class, 'subscribe']);
        Route::post('/cancel', [BillingController::class, 'cancel']);
        Route::post('/resume', [BillingController::class, 'resume']);
        Route::get('/invoices', [BillingController::class, 'invoices']);
        Route::get('/invoice/{id}', [BillingController::class, 'downloadInvoice']);
        Route::post('/payment-method', [BillingController::class, 'updatePaymentMethod']);
    });
});
