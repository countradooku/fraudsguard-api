<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class BlacklistedIP extends Model
{
    use HasFactory;

    /**
     * The table associated with the model.
     */
    protected $table = 'blacklisted_ips';

    /**
     * The attributes that are mass assignable.
     */
    protected $fillable = [
        'ip_hash',
        'ip_address',
        'ip_version',
        'reason',
        'risk_weight',
        'source',
        'metadata',
        'last_seen_at',
    ];

    /**
     * The attributes that should be cast.
     */
    protected $casts = [
        'metadata' => 'array',
        'risk_weight' => 'integer',
        'last_seen_at' => 'datetime',
    ];

    /**
     * Boot the model.
     */
    protected static function boot()
    {
        parent::boot();

        static::creating(function ($model) {
            if ($model->ip_address) {
                $model->ip_version = filter_var($model->ip_address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 'v4' : 'v6';
            }
        });
    }

    /**
     * Scope for IPv4 addresses.
     */
    public function scopeIpv4($query)
    {
        return $query->where('ip_version', 'v4');
    }

    /**
     * Scope for IPv6 addresses.
     */
    public function scopeIpv6($query)
    {
        return $query->where('ip_version', 'v6');
    }

    /**
     * Scope for active blacklist entries.
     */
    public function scopeActive($query)
    {
        return $query->where('risk_weight', '>', 0);
    }

    /**
     * Scope for specific source.
     */
    public function scopeFromSource($query, string $source)
    {
        return $query->where('source', $source);
    }

    /**
     * Check if IP is in CIDR range.
     */
    public function isInRange(string $cidr): bool
    {
        [$subnet, $mask] = explode('/', $cidr);

        if ($this->ip_version === 'v4') {
            return $this->ipv4InRange($this->ip_address, $subnet, $mask);
        } else {
            return $this->ipv6InRange($this->ip_address, $subnet, $mask);
        }
    }

    /**
     * Check if IPv4 is in range.
     */
    protected function ipv4InRange(string $ip, string $subnet, int $mask): bool
    {
        $ip = ip2long($ip);
        $subnet = ip2long($subnet);
        $netmask = -1 << (32 - $mask);
        $subnet &= $netmask;

        return ($ip & $netmask) === $subnet;
    }

    /**
     * Check if IPv6 is in range.
     */
    protected function ipv6InRange(string $ip, string $subnet, int $mask): bool
    {
        $ipBin = inet_pton($ip);
        $subnetBin = inet_pton($subnet);

        $ipBits = '';
        $subnetBits = '';

        for ($i = 0; $i < strlen($ipBin); $i++) {
            $ipBits .= str_pad(decbin(ord($ipBin[$i])), 8, '0', STR_PAD_LEFT);
            $subnetBits .= str_pad(decbin(ord($subnetBin[$i])), 8, '0', STR_PAD_LEFT);
        }

        return substr($ipBits, 0, $mask) === substr($subnetBits, 0, $mask);
    }

    /**
     * Update last seen timestamp.
     */
    public function updateLastSeen(): void
    {
        $this->update(['last_seen_at' => now()]);
    }
}
