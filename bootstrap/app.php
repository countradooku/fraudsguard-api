<?php

use App\Http\Middleware\LogApiUsageMiddleware;
use App\Models\ApiKey;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->statefulApi();

        // Register custom middleware aliases
        $middleware->alias([
            'api.auth' => \App\Http\Middleware\ApiAuthenticationMiddleware::class,
            'check.subscription' => \App\Http\Middleware\CheckSubscriptionMiddleware::class,
            'log.api.usage' => LogApiUsageMiddleware::class,
            'webhook.verify' => \App\Http\Middleware\VerifyWebhookSignatureMiddleware::class,
        ]);

        // Apply middleware to API routes
        $middleware->api(append: [
            LogApiUsageMiddleware::class,
        ]);

        $middleware->validateCsrfTokens(except: [
            'api/*',
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {})
    ->withSchedule(function ($schedule): void {
        $schedule->command('fraud:update-tor-nodes')
            ->everyFourHours()
            ->withoutOverlapping()
            ->runInBackground()
            ->appendOutputTo(storage_path('logs/tor-updates.log'));

        // Update disposable email domains daily
        $schedule->command('fraud:update-disposable-emails')
            ->daily()
            ->at('02:00')
            ->withoutOverlapping()
            ->runInBackground()
            ->appendOutputTo(storage_path('logs/disposable-emails-updates.log'));

        // Update ASN database weekly
        $schedule->command('fraud:update-asn')
            ->weekly()
            ->sundays()
            ->at('03:00')
            ->withoutOverlapping()
            ->runInBackground()
            ->appendOutputTo(storage_path('logs/asn-updates.log'));

        // Clean up old data monthly
        $schedule->command('fraud:cleanup-old-data')
            ->monthly()
            ->at('04:00')
            ->withoutOverlapping()
            ->runInBackground();

        // Reset free tier limits monthly
        $schedule->call(function () {
            \App\Models\User::where('free_checks_reset_at', '<=', now())
                ->whereDoesntHave('subscriptions', function ($query) {
                    $query->where('stripe_status', 'active');
                })
                ->each(function ($user) {
                    $user->resetFreeChecks();
                });
        })->daily()->at('00:00');

        // Generate daily usage reports
        $schedule->command('fraud:generate-usage-report')
            ->daily()
            ->at('01:00');

        // Check for expired API keys
        $schedule->call(function () {
            ApiKey::where('expires_at', '<=', now())
                ->where('is_active', true)
                ->update(['is_active' => false]);
        })->hourly();

        // Health checks
        $schedule->command('health:check')
            ->everyFiveMinutes()
            ->runInBackground();

        // Backup database
        if (config('app.env') === 'production') {
            $schedule->command('backup:clean')->daily()->at('01:00');
            $schedule->command('backup:run')->daily()->at('02:00');
        }
    })
    ->create();
