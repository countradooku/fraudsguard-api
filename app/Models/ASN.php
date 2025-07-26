<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ASN extends Model
{
    use HasFactory;

    /**
     * The table associated with the model.
     */
    protected $table = 'asns';

    /**
     * The attributes that are mass assignable.
     */
    protected $fillable = [
        'asn',
        'name',
        'organization',
        'country_code',
        'type',
        'risk_weight',
        'is_hosting',
        'is_vpn',
        'is_proxy',
        'ip_ranges',
        'verified_at',
    ];

    /**
     * The attributes that should be cast.
     */
    protected $casts = [
        'asn' => 'integer',
        'risk_weight' => 'integer',
        'is_hosting' => 'boolean',
        'is_vpn' => 'boolean',
        'is_proxy' => 'boolean',
        'ip_ranges' => 'array',
        'verified_at' => 'datetime',
    ];

    /**
     * Scope for hosting providers.
     */
    public function scopeHosting($query)
    {
        return $query->where('is_hosting', true);
    }

    /**
     * Scope for VPN providers.
     */
    public function scopeVpn($query)
    {
        return $query->where('is_vpn', true);
    }

    /**
     * Scope for proxy providers.
     */
    public function scopeProxy($query)
    {
        return $query->where('is_proxy', true);
    }

    /**
     * Scope for specific type.
     */
    public function scopeOfType($query, string $type)
    {
        return $query->where('type', $type);
    }

    /**
     * Scope for high risk ASNs.
     */
    public function scopeHighRisk($query)
    {
        return $query->where('risk_weight', '>=', 50);
    }

    /**
     * Scope for specific country.
     */
    public function scopeFromCountry($query, string $countryCode)
    {
        return $query->where('country_code', $countryCode);
    }

    /**
     * Check if an IP belongs to this ASN.
     */
    public function containsIP(string $ip): bool
    {
        if (empty($this->ip_ranges)) {
            return false;
        }

        foreach ($this->ip_ranges as $range) {
            if ($this->ipInRange($ip, $range)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if IP is in CIDR range.
     */
    protected function ipInRange(string $ip, string $cidr): bool
    {
        if (strpos($cidr, '/') === false) {
            return $ip === $cidr;
        }

        [$subnet, $mask] = explode('/', $cidr);

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $this->ipv4InRange($ip, $subnet, $mask);
        } else {
            return $this->ipv6InRange($ip, $subnet, $mask);
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
     * Get display name for the ASN.
     */
    public function getDisplayNameAttribute(): string
    {
        return "AS{$this->asn} - {$this->organization}";
    }
}
