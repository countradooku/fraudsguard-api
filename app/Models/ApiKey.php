<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class ApiKey extends Model
{
    use HasFactory;

    /**
     * The attributes that are mass assignable.
     */
    protected $fillable = [
        'user_id',
        'name',
        'key',
        'secret_hash',
        'permissions',
        'rate_limit',
        'last_used_at',
        'expires_at',
        'is_active',
    ];

    /**
     * The attributes that should be cast.
     */
    protected $casts = [
        'permissions' => 'array',
        'last_used_at' => 'datetime',
        'expires_at' => 'datetime',
        'is_active' => 'boolean',
    ];

    /**
     * The attributes that should be hidden for serialization.
     */
    protected $hidden = [
        'secret_hash',
    ];

    /**
     * Get the user that owns the API key.
     */
    public function user()
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Get the fraud checks made with this API key.
     */
    public function fraudChecks()
    {
        return $this->hasMany(FraudCheck::class);
    }

    /**
     * Get the API usage records for this key.
     */
    public function apiUsage()
    {
        return $this->hasMany(ApiUsage::class);
    }

    /**
     * Generate a new API key and secret.
     */
    public static function generate(User $user, string $name, array $attributes = []): array
    {
        $key = 'fdk_'.Str::random(32); // fdk = FrauD Key
        $secret = 'fds_'.Str::random(48); // fds = FrauD Secret

        $apiKey = self::create(array_merge([
            'user_id' => $user->id,
            'name' => $name,
            'key' => $key,
            'secret_hash' => Hash::make($secret),
            'rate_limit' => $user->getRateLimit(),
        ], $attributes));

        return [
            'key' => $key,
            'secret' => $secret,
            'model' => $apiKey,
        ];
    }

    /**
     * Verify a secret against the stored hash.
     */
    public function verifySecret(string $secret): bool
    {
        return Hash::check($secret, $this->secret_hash);
    }

    /**
     * Check if the API key is valid.
     */
    public function isValid(): bool
    {
        if (! $this->is_active) {
            return false;
        }

        if ($this->expires_at && $this->expires_at->isPast()) {
            return false;
        }

        return true;
    }

    /**
     * Check if the API key has a specific permission.
     */
    public function hasPermission(string $permission): bool
    {
        if (empty($this->permissions)) {
            return true; // All permissions if none specified
        }

        return in_array($permission, $this->permissions) ||
            in_array('*', $this->permissions);
    }

    /**
     * Update the last used timestamp.
     */
    public function markAsUsed(): void
    {
        $this->update(['last_used_at' => now()]);
    }

    /**
     * Revoke the API key.
     */
    public function revoke(): void
    {
        $this->update(['is_active' => false]);
    }

    /**
     * Get usage statistics for this API key.
     */
    public function getUsageStats(string $period = 'month'): array
    {
        $query = $this->apiUsage();

        switch ($period) {
            case 'day':
                $startDate = now()->startOfDay();
                break;
            case 'week':
                $startDate = now()->startOfWeek();
                break;
            case 'month':
            default:
                $startDate = now()->startOfMonth();
                break;
        }

        $stats = $query->where('created_at', '>=', $startDate)
            ->selectRaw('
                COUNT(*) as total_requests,
                SUM(CASE WHEN response_code >= 200 AND response_code < 300 THEN 1 ELSE 0 END) as successful_requests,
                SUM(CASE WHEN response_code >= 400 THEN 1 ELSE 0 END) as failed_requests,
                SUM(CASE WHEN is_billable THEN 1 ELSE 0 END) as billable_requests,
                SUM(CASE WHEN is_over_limit THEN 1 ELSE 0 END) as over_limit_requests,
                AVG(response_time_ms) as avg_response_time,
                SUM(cost) as total_cost
            ')
            ->first();

        return [
            'period' => $period,
            'start_date' => $startDate->toDateTimeString(),
            'total_requests' => $stats->total_requests ?? 0,
            'successful_requests' => $stats->successful_requests ?? 0,
            'failed_requests' => $stats->failed_requests ?? 0,
            'billable_requests' => $stats->billable_requests ?? 0,
            'over_limit_requests' => $stats->over_limit_requests ?? 0,
            'average_response_time' => round($stats->avg_response_time ?? 0, 2),
            'total_cost' => round($stats->total_cost ?? 0, 2),
        ];
    }

    /**
     * Get the current hour's usage count.
     */
    public function getCurrentHourUsage(): int
    {
        return $this->apiUsage()
            ->where('created_at', '>=', now()->startOfHour())
            ->count();
    }

    /**
     * Check if rate limit is exceeded.
     */
    public function isRateLimitExceeded(): bool
    {
        return $this->getCurrentHourUsage() >= $this->rate_limit;
    }
}
