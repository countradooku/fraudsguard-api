<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Facades\Crypt;

class FraudCheck extends Model
{
    use HasFactory;

    /**
     * The attributes that are mass assignable.
     */
    protected $fillable = [
        'user_id',
        'api_key_id',
        'email_hash',
        'ip_hash',
        'credit_card_hash',
        'phone_hash',
        'email_encrypted',
        'ip_encrypted',
        'credit_card_encrypted',
        'phone_encrypted',
        'user_agent',
        'domain',
        'headers',
        'risk_score',
        'check_results',
        'failed_checks',
        'passed_checks',
        'decision',
        'processing_time_ms',
    ];

    /**
     * The attributes that should be cast.
     */
    protected $casts = [
        'headers' => 'array',
        'check_results' => 'array',
        'failed_checks' => 'array',
        'passed_checks' => 'array',
        'risk_score' => 'integer',
        'processing_time_ms' => 'integer',
    ];

    /**
     * The attributes that should be hidden for serialization.
     */
    protected $hidden = [
        'email_encrypted',
        'ip_encrypted',
        'credit_card_encrypted',
        'phone_encrypted',
        'email_hash',
        'ip_hash',
        'credit_card_hash',
        'phone_hash',
    ];

    /**
     * Get the user that owns the fraud check.
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Get the API key used for this check.
     */
    public function apiKey(): BelongsTo
    {
        return $this->belongsTo(ApiKey::class);
    }

    /**
     * Decrypt email if needed.
     */
    public function getEmailAttribute(): ?string
    {
        if ($this->email_encrypted) {
            try {
                return Crypt::decryptString($this->email_encrypted);
            } catch (\Exception $e) {
                return null;
            }
        }

        return null;
    }

    /**
     * Decrypt IP if needed.
     */
    public function getIpAttribute(): ?string
    {
        if ($this->ip_encrypted) {
            try {
                return Crypt::decryptString($this->ip_encrypted);
            } catch (\Exception $e) {
                return null;
            }
        }

        return null;
    }

    /**
     * Get masked credit card number.
     */
    public function getMaskedCreditCardAttribute(): ?string
    {
        if ($this->credit_card_encrypted) {
            try {
                $decrypted = Crypt::decryptString($this->credit_card_encrypted);

                // Return last 4 digits only
                return '****'.substr($decrypted, -4);
            } catch (\Exception $e) {
                return null;
            }
        }

        return null;
    }

    /**
     * Get masked phone number.
     */
    public function getMaskedPhoneAttribute(): ?string
    {
        if ($this->phone_encrypted) {
            try {
                $decrypted = Crypt::decryptString($this->phone_encrypted);

                // Return last 4 digits only
                return '***'.substr($decrypted, -4);
            } catch (\Exception $e) {
                return null;
            }
        }

        return null;
    }

    /**
     * Scope for high risk checks.
     */
    public function scopeHighRisk($query)
    {
        return $query->where('risk_score', '>=', 80);
    }

    /**
     * Scope for blocked checks.
     */
    public function scopeBlocked($query)
    {
        return $query->where('decision', 'block');
    }

    /**
     * Scope for checks requiring review.
     */
    public function scopeNeedsReview($query)
    {
        return $query->where('decision', 'review');
    }

    /**
     * Get the risk level.
     */
    public function getRiskLevelAttribute(): string
    {
        if ($this->risk_score >= 80) {
            return 'critical';
        } elseif ($this->risk_score >= 50) {
            return 'high';
        } elseif ($this->risk_score >= 30) {
            return 'medium';
        } else {
            return 'low';
        }
    }

    /**
     * Get checks that failed.
     */
    public function getFailedCheckNamesAttribute(): array
    {
        return array_keys($this->failed_checks ?? []);
    }

    /**
     * Get checks that passed.
     */
    public function getPassedCheckNamesAttribute(): array
    {
        return array_keys($this->passed_checks ?? []);
    }

    /**
     * Check if a specific check failed.
     */
    public function checkFailed(string $checkName): bool
    {
        return isset($this->failed_checks[$checkName]);
    }

    /**
     * Get the summary for API response.
     */
    public function toApiResponse(): array
    {
        return [
            'id' => $this->id,
            'risk_score' => $this->risk_score,
            'risk_level' => $this->risk_level,
            'decision' => $this->decision,
            'checks_performed' => count($this->check_results ?? []),
            'failed_checks' => count($this->failed_checks ?? []),
            'passed_checks' => count($this->passed_checks ?? []),
            'processing_time_ms' => $this->processing_time_ms,
            'created_at' => $this->created_at->toIso8601String(),
        ];
    }
}
