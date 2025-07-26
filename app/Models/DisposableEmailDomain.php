<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class DisposableEmailDomain extends Model
{
    use HasFactory;

    /**
     * The attributes that are mass assignable.
     */
    protected $fillable = [
        'domain',
        'source',
        'risk_weight',
        'is_active',
        'verified_at',
    ];

    /**
     * The attributes that should be cast.
     */
    protected $casts = [
        'risk_weight' => 'integer',
        'is_active' => 'boolean',
        'verified_at' => 'datetime',
    ];

    /**
     * Boot the model.
     */
    protected static function boot()
    {
        parent::boot();

        static::creating(function ($model) {
            // Always store domains in lowercase
            $model->domain = strtolower($model->domain);
        });

        static::updating(function ($model) {
            // Always store domains in lowercase
            $model->domain = strtolower($model->domain);
        });
    }

    /**
     * Scope for active domains.
     */
    public function scopeActive($query)
    {
        return $query->where('is_active', true);
    }

    /**
     * Scope for verified domains.
     */
    public function scopeVerified($query)
    {
        return $query->whereNotNull('verified_at');
    }

    /**
     * Scope for domains from specific source.
     */
    public function scopeFromSource($query, string $source)
    {
        return $query->where('source', $source);
    }

    /**
     * Mark domain as verified.
     */
    public function markAsVerified(): void
    {
        $this->update(['verified_at' => now()]);
    }

    /**
     * Check if domain needs reverification.
     */
    public function needsReverification(): bool
    {
        // Reverify if not verified in 30 days
        return ! $this->verified_at ||
            $this->verified_at->lt(now()->subDays(30));
    }
}
