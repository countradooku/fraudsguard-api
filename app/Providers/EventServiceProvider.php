<?php

namespace App\Providers;

use App\Events\FraudCheckPerformedEvent;
use App\Events\HighRiskDetectedEvent;
use App\Listeners\LogFraudCheckListener;
use App\Listeners\NotifyHighRiskListener;
use App\Listeners\SendWebhookNotificationListener;
use App\Listeners\UpdateUsageStatsListener;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Listeners\SendEmailVerificationNotification;
use Illuminate\Foundation\Support\Providers\EventServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Event;

class EventServiceProvider extends ServiceProvider
{
    /**
     * The event to listener mappings for the application.
     *
     * @var array<class-string, array<int, class-string>>
     */
    protected $listen = [
        Registered::class => [
            SendEmailVerificationNotification::class,
        ],

        FraudCheckPerformedEvent::class => [
            LogFraudCheckListener::class,
            UpdateUsageStatsListener::class,
            SendWebhookNotificationListener::class,
        ],

        HighRiskDetectedEvent::class => [
            NotifyHighRiskListener::class,
        ],

        'Laravel\Cashier\Events\WebhookReceived' => [
            'App\Listeners\StripeEventListener',
        ],

        'Laravel\Cashier\Events\WebhookHandled' => [
            'App\Listeners\LogStripeWebhook',
        ],
    ];

    /**
     * Register any events for your application.
     */
    public function boot(): void
    {
        parent::boot();

        // Register model events
        \App\Models\User::created(function ($user) {
            // Reset free tier limits for new users
            $user->update([
                'free_checks_remaining' => config('fraud-detection.free_tier_limit', 100),
                'free_checks_reset_at' => now()->addMonth(),
            ]);
        });

        \App\Models\FraudCheck::created(function ($fraudCheck) {
            // Check if high risk and dispatch event
            if ($fraudCheck->risk_score >= 80) {
                event(new HighRiskDetectedEvent($fraudCheck));
            }
        });
    }

    /**
     * Determine if events and listeners should be automatically discovered.
     */
    public function shouldDiscoverEvents(): bool
    {
        return false;
    }
}
