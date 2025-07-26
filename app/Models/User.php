<?php

namespace App\Models;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Cashier\Billable;
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable implements MustVerifyEmail
{
    use Billable, HasApiTokens, HasFactory, Notifiable;

    /**
     * The attributes that are mass assignable.
     */
    protected $fillable = [
        'name',
        'email',
        'password',
        'company_name',
        'free_checks_remaining',
        'free_checks_reset_at',
    ];

    /**
     * The attributes that should be hidden for serialization.
     */
    protected $hidden = [
        'password',
        'remember_token',
        'stripe_id',
        'pm_type',
        'pm_last_four',
    ];

    /**
     * The attributes that should be cast.
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
        'trial_ends_at' => 'datetime',
        'free_checks_reset_at' => 'datetime',
    ];

    /**
     * Get the user's API keys
     */
    public function apiKeys(): User|HasMany
    {
        return $this->hasMany(ApiKey::class);
    }

    /**
     * Get the user's fraud checks
     */
    public function fraudChecks(): User|HasMany
    {
        return $this->hasMany(FraudCheck::class);
    }

    /**
     * Get the user's API usage records
     */
    public function apiUsage(): User|HasMany
    {
        return $this->hasMany(ApiUsage::class);
    }

    /**
     * Get active API keys
     */
    public function activeApiKeys()
    {
        return $this->apiKeys()->where('is_active', true);
    }

    /**
     * Check if user has reached free tier limit
     */
    public function hasReachedFreeLimit(): bool
    {
        if ($this->subscribed('default')) {
            return false;
        }

        return $this->free_checks_remaining <= 0;
    }

    /**
     * Reset free checks (monthly)
     */
    public function resetFreeChecks(): void
    {
        $this->update([
            'free_checks_remaining' => config('fraud-detection.free_tier_limit', 100),
            'free_checks_reset_at' => now()->addMonth(),
        ]);
    }

    /**
     * Get current plan name
     */
    public function getCurrentPlan(): string
    {
        if (! $this->subscribed('default')) {
            return 'free';
        }

        $subscription = $this->subscription('default');

        // Map Stripe price IDs to plan names
        $plans = [
            config('cashier.plans.basic.price_id') => 'basic',
            config('cashier.plans.pro.price_id') => 'pro',
            config('cashier.plans.enterprise.price_id') => 'enterprise',
        ];

        foreach ($subscription->items as $item) {
            if (isset($plans[$item->stripe_price])) {
                return $plans[$item->stripe_price];
            }
        }

        return 'unknown';
    }

    /**
     * Get rate limit based on plan
     */
    public function getRateLimit(): int
    {
        $plan = $this->getCurrentPlan();

        return match ($plan) {
            'basic' => config('fraud-detection.rate_limits.basic', 1000),
            'pro' => config('fraud-detection.rate_limits.pro', 10000),
            'enterprise' => config('fraud-detection.rate_limits.enterprise', 100000),
            default => config('fraud-detection.rate_limits.free', 100),
        };
    }

    /**
     * Get API usage for current billing period
     */
    public function getCurrentBillingPeriodUsage(): int
    {
        $subscription = $this->subscription('default');

        if (! $subscription) {
            // Free tier - count from reset date
            $startDate = $this->free_checks_reset_at ?
                $this->free_checks_reset_at->subMonth() :
                $this->created_at;
        } else {
            // Paid tier - count from subscription period
            $startDate = $subscription->asStripeSubscription()->current_period_start;
            $startDate = \Carbon\Carbon::createFromTimestamp($startDate);
        }

        return $this->apiUsage()
            ->where('created_at', '>=', $startDate)
            ->where('is_billable', true)
            ->count();
    }

    /**
     * Get overage charges for current period
     */
    public function getOverageCharges(): float
    {
        if (! $this->subscribed('default')) {
            return 0;
        }

        $usage = $this->apiUsage()
            ->where('is_over_limit', true)
            ->where('created_at', '>=', now()->startOfMonth())
            ->sum('cost');

        return $usage;
    }

    /**
     * Record API usage
     */
    public function recordApiUsage(array $data): ApiUsage
    {
        return $this->apiUsage()->create($data);
    }

    /**
     * Get fraud check statistics
     */
    public function getFraudCheckStats(): array
    {
        $checks = $this->fraudChecks()
            ->selectRaw('
                COUNT(*) as total,
                AVG(risk_score) as avg_risk_score,
                SUM(CASE WHEN decision = \'allow\' THEN 1 ELSE 0 END) as allowed,
                SUM(CASE WHEN decision = \'review\' THEN 1 ELSE 0 END) as review,
                SUM(CASE WHEN decision = \'block\' THEN 1 ELSE 0 END) as blocked,
                AVG(processing_time_ms) as avg_processing_time
            ')
            ->first();

        return [
            'total_checks' => $checks->total ?? 0,
            'average_risk_score' => round($checks->avg_risk_score ?? 0, 2),
            'allowed' => $checks->allowed ?? 0,
            'review' => $checks->review ?? 0,
            'blocked' => $checks->blocked ?? 0,
            'average_processing_time' => round($checks->avg_processing_time ?? 0, 2),
        ];
    }

    /**
     * Get recent fraud checks
     */
    public function getRecentFraudChecks(int $limit = 10)
    {
        return $this->fraudChecks()
            ->orderBy('created_at', 'desc')
            ->limit($limit)
            ->get();
    }
}
