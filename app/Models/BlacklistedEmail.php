<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class BlacklistedEmail extends Model
{
    use HasFactory;

    /**
     * The attributes that are mass assignable.
     */
    protected $fillable = [
        'email_hash',
        'reason',
        'risk_weight',
        'reported_by',
        'report_count',
        'last_seen_at',
    ];

    /**
     * The attributes that should be cast.
     */
    protected $casts = [
        'risk_weight' => 'integer',
        'report_count' => 'integer',
        'last_seen_at' => 'datetime',
    ];

    /**
     * Get the user who reported this email.
     */
    public function reporter()
    {
        return $this->belongsTo(User::class, 'reported_by');
    }

    /**
     * Increment report count and update last seen.
     */
    public function incrementReport(): void
    {
        $this->increment('report_count');
        $this->update(['last_seen_at' => now()]);
    }

    /**
     * Scope for active blacklist entries.
     */
    public function scopeActive($query)
    {
        return $query->where('risk_weight', '>', 0);
    }

    /**
     * Scope for high risk entries.
     */
    public function scopeHighRisk($query)
    {
        return $query->where('risk_weight', '>=', 80);
    }

    /**
     * Check if should auto-expire.
     */
    public function shouldExpire(): bool
    {
        // Auto-expire if not seen in 6 months and low report count
        return $this->last_seen_at->lt(now()->subMonths(6)) &&
            $this->report_count < 5;
    }
}
