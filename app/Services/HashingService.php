<?php

namespace App\Services;

use Illuminate\Support\Facades\Config;

class HashingService
{
    protected string $algorithm;

    protected string $key;

    public function __construct()
    {
        $this->algorithm = Config::get('fraud-detection.hashing.algorithm', 'sha256');
        $this->key = Config::get('fraud-detection.hashing.key');

        if (empty($this->key)) {
            throw new \RuntimeException('Fraud detection hash key is not configured');
        }
    }

    /**
     * Create a secure hash of the given value
     */
    public function hash(string $value): string
    {
        // Normalize the value (lowercase, trim)
        $normalized = strtolower(trim($value));

        // Create HMAC hash for security
        return hash_hmac($this->algorithm, $normalized, $this->key);
    }

    /**
     * Verify if a value matches a hash
     */
    public function verify(string $value, string $hash): bool
    {
        return hash_equals($this->hash($value), $hash);
    }

    /**
     * Create a partial hash for prefix matching
     * Useful for searching while maintaining privacy
     */
    public function partialHash(string $value, int $length = 8): string
    {
        return substr($this->hash($value), 0, $length);
    }

    /**
     * Hash an array of values
     */
    public function hashArray(array $values): array
    {
        return array_map([$this, 'hash'], $values);
    }

    /**
     * Create a composite hash from multiple values
     * Useful for creating unique identifiers from multiple fields
     */
    public function compositeHash(array $values): string
    {
        // Sort to ensure consistent ordering
        sort($values);

        // Join with a delimiter that won't appear in the values
        $composite = implode('|', $values);

        return $this->hash($composite);
    }

    /**
     * Generate a hash suitable for database indexing
     * Shorter than full hash but still unique enough
     */
    public function indexHash(string $value): string
    {
        // Use first 16 characters of hash for indexing
        return substr($this->hash($value), 0, 16);
    }
}
