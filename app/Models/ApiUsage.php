<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ApiUsage extends Model
{
    use HasFactory;

    /**
     * The table associated with the model.
     */
    protected $table = 'api_usages';

    /**
     * Indicates if the model should be timestamped.
     */
    public $timestamps = false;

    /**
     * The attributes that are mass assignable.
     */
    protected $fillable = [
        'user_id',
        'api_key_id',
        'endpoint',
        'method',
        'response_code',
        'response_time_ms',
        'is_billable',
        'is_over_limit',
        'cost',
        'ip_address',
        'request_headers',
        'request_body',
        'created_at',
    ];

    /**
     * The attributes that should be cast.
     */
    protected $casts = [
        'request_headers' => 'array',
        'request_body' => 'array',
        'is_billable' => 'boolean',
        'is_over_limit' => 'boolean',
        'cost' => 'decimal:6',
        'response_time_ms' => 'integer',
        'response_code' => 'integer',
        'created_at' => 'datetime',
    ];

    /**
     * The attributes that should be hidden for serialization.
     */
    protected $hidden = [
        'request_body',
        'request_headers',
    ];

    /**
     * Get the user that owns the API usage.
     */
    public function user()
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Get the API key used for this request.
     */
    public function apiKey()
    {
        return $this->belongsTo(ApiKey::class);
    }

    /**
     * Scope for billable requests.
     */
    public function scopeBillable($query)
    {
        return $query->where('is_billable', true);
    }

    /**
     * Scope for successful requests.
     */
    public function scopeSuccessful($query)
    {
        return $query->whereBetween('response_code', [200, 299]);
    }

    /**
     * Scope for failed requests.
     */
    public function scopeFailed($query)
    {
        return $query->where('response_code', '>=', 400);
    }

    /**
     * Scope for overage requests.
     */
    public function scopeOverage($query)
    {
        return $query->where('is_over_limit', true);
    }

    /**
     * Get the endpoint name without parameters.
     */
    public function getCleanEndpointAttribute(): string
    {
        // Remove IDs and parameters from endpoint
        return preg_replace('/\/\d+/', '/{id}', $this->endpoint);
    }

    /**
     * Check if the request was successful.
     */
    public function getIsSuccessfulAttribute(): bool
    {
        return $this->response_code >= 200 && $this->response_code < 300;
    }

    /**
     * Get human-readable response time.
     */
    public function getFormattedResponseTimeAttribute(): string
    {
        if ($this->response_time_ms < 1000) {
            return $this->response_time_ms.'ms';
        }

        return round($this->response_time_ms / 1000, 2).'s';
    }

    /**
     * Get the status type.
     */
    public function getStatusTypeAttribute(): string
    {
        if ($this->response_code < 200) {
            return 'info';
        } elseif ($this->response_code < 300) {
            return 'success';
        } elseif ($this->response_code < 400) {
            return 'redirect';
        } elseif ($this->response_code < 500) {
            return 'client_error';
        } else {
            return 'server_error';
        }
    }
}
