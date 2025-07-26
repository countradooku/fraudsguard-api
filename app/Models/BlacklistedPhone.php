<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class BlacklistedPhone extends Model
{
    use HasFactory;

    /**
     * The attributes that are mass assignable.
     */
    protected $fillable = [
        'phone_hash',
        'country_code',
        'reason',
        'risk_weight',
        'type',
        'last_seen_at',
    ];

    /**
     * The attributes that should be cast.
     */
    protected $casts = [
        'risk_weight' => 'integer',
        'last_seen_at' => 'datetime',
    ];

    /**
     * Scope for specific phone type.
     */
    public function scopeOfType($query, string $type)
    {
        return $query->where('type', $type);
    }

    /**
     * Scope for specific country.
     */
    public function scopeFromCountry($query, string $countryCode)
    {
        return $query->where('country_code', $countryCode);
    }

    /**
     * Scope for VOIP numbers.
     */
    public function scopeVoip($query)
    {
        return $query->where('type', 'voip');
    }

    /**
     * Update last seen timestamp.
     */
    public function updateLastSeen(): void
    {
        $this->update(['last_seen_at' => now()]);
    }

    /**
     * Check if should auto-expire.
     */
    public function shouldExpire(): bool
    {
        // Auto-expire if not seen in 6 months
        return $this->last_seen_at->lt(now()->subMonths(6));
    }
}
