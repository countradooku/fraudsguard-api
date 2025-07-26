<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class KnownUserAgent extends Model
{
    use HasFactory;

    /**
     * The attributes that are mass assignable.
     */
    protected $fillable = [
        'user_agent',
        'user_agent_hash',
        'type',
        'name',
        'version',
        'risk_weight',
        'is_outdated',
        'eol_date',
    ];

    /**
     * The attributes that should be cast.
     */
    protected $casts = [
        'risk_weight' => 'integer',
        'is_outdated' => 'boolean',
        'eol_date' => 'date',
    ];

    /**
     * Boot the model.
     */
    protected static function boot()
    {
        parent::boot();

        static::creating(function ($model) {
            if ($model->user_agent && ! $model->user_agent_hash) {
                $model->user_agent_hash = hash('sha256', $model->user_agent);
            }
        });
    }

    /**
     * Scope for specific type.
     */
    public function scopeOfType($query, string $type)
    {
        return $query->where('type', $type);
    }

    /**
     * Scope for bots.
     */
    public function scopeBots($query)
    {
        return $query->where('type', 'bot');
    }

    /**
     * Scope for scrapers.
     */
    public function scopeScrapers($query)
    {
        return $query->where('type', 'scraper');
    }

    /**
     * Scope for malicious agents.
     */
    public function scopeMalicious($query)
    {
        return $query->where('type', 'malicious');
    }

    /**
     * Scope for outdated agents.
     */
    public function scopeOutdated($query)
    {
        return $query->where('is_outdated', true);
    }

    /**
     * Check if user agent is past EOL.
     */
    public function isPastEOL(): bool
    {
        return $this->eol_date && $this->eol_date->isPast();
    }

    /**
     * Mark as outdated if past EOL.
     */
    public function checkEOL(): void
    {
        if ($this->isPastEOL() && ! $this->is_outdated) {
            $this->update(['is_outdated' => true]);
        }
    }

    /**
     * Get display name.
     */
    public function getDisplayNameAttribute(): string
    {
        if ($this->name && $this->version) {
            return "{$this->name} {$this->version}";
        }

        return $this->name ?: 'Unknown';
    }
}
