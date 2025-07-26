<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class TorExitNode extends Model
{
    use HasFactory;

    /**
     * The attributes that are mass assignable.
     */
    protected $fillable = [
        'ip_address',
        'ip_version',
        'node_id',
        'nickname',
        'risk_weight',
        'is_active',
        'last_seen_at',
    ];

    /**
     * The attributes that should be cast.
     */
    protected $casts = [
        'risk_weight' => 'integer',
        'is_active' => 'boolean',
        'last_seen_at' => 'datetime',
    ];

    /**
     * Boot the model.
     */
    protected static function boot()
    {
        parent::boot();

        static::creating(function ($model) {
            if ($model->ip_address && ! $model->ip_version) {
                $model->ip_version = filter_var($model->ip_address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 'v4' : 'v6';
            }
        });
    }

    /**
     * Scope for active nodes.
     */
    public function scopeActive($query)
    {
        return $query->where('is_active', true);
    }

    /**
     * Scope for IPv4 nodes.
     */
    public function scopeIpv4($query)
    {
        return $query->where('ip_version', 'v4');
    }

    /**
     * Scope for IPv6 nodes.
     */
    public function scopeIpv6($query)
    {
        return $query->where('ip_version', 'v6');
    }

    /**
     * Scope for recently seen nodes.
     */
    public function scopeRecentlySeen($query, int $hours = 24)
    {
        return $query->where('last_seen_at', '>=', now()->subHours($hours));
    }

    /**
     * Mark as inactive if not seen recently.
     */
    public function checkActivity(): void
    {
        // Mark as inactive if not seen in 48 hours
        if ($this->last_seen_at->lt(now()->subHours(48))) {
            $this->update(['is_active' => false]);
        }
    }

    /**
     * Get display name for the node.
     */
    public function getDisplayNameAttribute(): string
    {
        if ($this->nickname) {
            return "{$this->nickname} ({$this->ip_address})";
        }

        return $this->ip_address;
    }
}
