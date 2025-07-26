<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class BlacklistedCreditCard extends Model
{
    use HasFactory;

    /**
     * The attributes that are mass assignable.
     */
    protected $fillable = [
        'card_hash',
        'card_type',
        'last_four',
        'reason',
        'risk_weight',
        'chargeback_count',
        'total_chargeback_amount',
        'last_seen_at',
    ];

    /**
     * The attributes that should be cast.
     */
    protected $casts = [
        'risk_weight' => 'integer',
        'chargeback_count' => 'integer',
        'total_chargeback_amount' => 'decimal:2',
        'last_seen_at' => 'datetime',
    ];

    /**
     * Boot the model.
     */
    protected static function boot()
    {
        parent::boot();

        static::creating(function ($model) {
            // Ensure last_four is always 4 digits
            if ($model->last_four) {
                $model->last_four = substr($model->last_four, -4);
            }
        });
    }

    /**
     * Add a chargeback record.
     */
    public function addChargeback(float $amount): void
    {
        $this->increment('chargeback_count');
        $this->increment('total_chargeback_amount', $amount);
        $this->update(['last_seen_at' => now()]);

        // Increase risk weight based on chargebacks
        if ($this->chargeback_count >= 3) {
            $this->update(['risk_weight' => 100]);
        } elseif ($this->chargeback_count >= 2) {
            $this->update(['risk_weight' => max($this->risk_weight, 80)]);
        }
    }

    /**
     * Scope for specific card type.
     */
    public function scopeOfType($query, string $type)
    {
        return $query->where('card_type', $type);
    }

    /**
     * Scope for high chargeback cards.
     */
    public function scopeHighChargeback($query)
    {
        return $query->where('chargeback_count', '>=', 2);
    }

    /**
     * Get formatted chargeback amount.
     */
    public function getFormattedChargebackAmountAttribute(): string
    {
        return '$'.number_format($this->total_chargeback_amount, 2);
    }

    /**
     * Check if card should be auto-removed from blacklist.
     */
    public function shouldExpire(): bool
    {
        // Remove from blacklist if not seen in 1 year and no chargebacks
        return $this->last_seen_at->lt(now()->subYear()) &&
            $this->chargeback_count === 0;
    }
}
