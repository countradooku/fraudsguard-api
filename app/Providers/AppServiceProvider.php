<?php

namespace App\Providers;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Resources\Json\JsonResource;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\ServiceProvider;
use Laravel\Sanctum\PersonalAccessToken;
use Laravel\Sanctum\Sanctum;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        // Register Fortify
        //        $this->app->register(FortifyServiceProvider::class);

        // Register custom service providers
        $this->app->register(FraudDetectionServiceProvider::class);
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // Fix for older MySQL versions
        Schema::defaultStringLength(191);

        // Disable wrapping of API resources
        JsonResource::withoutWrapping();

        // Use custom Sanctum model if needed
        Sanctum::usePersonalAccessTokenModel(PersonalAccessToken::class);

        // Load custom health checks
        $this->loadHealthChecks();

        // Configure rate limiting
        $this->configureRateLimiting();
    }

    /**
     * Load health check configurations
     */
    protected function loadHealthChecks(): void
    {
        // Custom health checks can be added here
    }

    /**
     * Configure rate limiting for the application
     */
    protected function configureRateLimiting(): void
    {
        RateLimiter::for('fraud-check', function ($request) {
            $apiKey = $request->apiKey;

            if (!$apiKey) {
                return Limit::perHour(10);
            }

            return Limit::perHour($apiKey->rate_limit)
                ->by($apiKey->id);
        });
    }
}
