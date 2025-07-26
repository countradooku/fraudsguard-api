<?php

namespace App\Providers;

use App\Services\FraudDetection\Checks\CreditCardCheck;
use App\Services\FraudDetection\Checks\DomainCheck;
use App\Services\FraudDetection\Checks\EmailCheck;
use App\Services\FraudDetection\Checks\IPCheck;
use App\Services\FraudDetection\Checks\PhoneCheck;
use App\Services\FraudDetection\Checks\UserAgentCheck;
use App\Services\FraudDetection\FraudDetectionService;
use App\Services\FraudDetection\Scorers\RiskScorer;
use App\Services\HashingService;
use Illuminate\Support\ServiceProvider;

class FraudDetectionServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        // Register HashingService as singleton
        $this->app->singleton(HashingService::class, function ($app) {
            return new HashingService;
        });

        // Register RiskScorer as singleton
        $this->app->singleton(RiskScorer::class, function ($app) {
            return new RiskScorer;
        });

        // Register individual checks
        $this->app->bind(EmailCheck::class, function ($app) {
            return new EmailCheck($app->make(HashingService::class));
        });

        $this->app->bind(DomainCheck::class, function ($app) {
            return new DomainCheck;
        });

        $this->app->bind(IPCheck::class, function ($app) {
            return new IPCheck($app->make(HashingService::class));
        });

        $this->app->bind(CreditCardCheck::class, function ($app) {
            return new CreditCardCheck($app->make(HashingService::class));
        });

        $this->app->bind(PhoneCheck::class, function ($app) {
            return new PhoneCheck($app->make(HashingService::class));
        });

        $this->app->bind(UserAgentCheck::class, function ($app) {
            return new UserAgentCheck;
        });

        // Register main FraudDetectionService
        $this->app->singleton(FraudDetectionService::class, function ($app) {
            return new FraudDetectionService(
                $app->make(HashingService::class),
                $app->make(RiskScorer::class),
                $app->make(EmailCheck::class),
                $app->make(DomainCheck::class),
                $app->make(IPCheck::class),
                $app->make(CreditCardCheck::class),
                $app->make(PhoneCheck::class),
                $app->make(UserAgentCheck::class)
            );
        });
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        // Schedule data source updates
        $this->app->booted(function () {
            $schedule = $this->app->make(\Illuminate\Console\Scheduling\Schedule::class);

            // Update Tor exit nodes every 6 hours
            $schedule->command('fraud:update-tor-nodes')
                ->cron(config('fraud-detection.update_schedules.tor_exit_nodes', '0 */6 * * *'))
                ->withoutOverlapping()
                ->runInBackground();

            // Update disposable email domains daily
            $schedule->command('fraud:update-disposable-emails')
                ->cron(config('fraud-detection.update_schedules.disposable_emails', '0 0 * * *'))
                ->withoutOverlapping()
                ->runInBackground();

            // Update ASN database weekly
            $schedule->command('fraud:update-asn')
                ->cron(config('fraud-detection.update_schedules.asn_database', '0 0 * * 0'))
                ->withoutOverlapping()
                ->runInBackground();

            // Clean up old data monthly
            $schedule->command('fraud:cleanup-old-data')
                ->monthly()
                ->withoutOverlapping()
                ->runInBackground();
        });
    }
}
