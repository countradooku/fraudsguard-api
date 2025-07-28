<?php

namespace App\Services;

use Illuminate\Support\Facades\Log;

class MemoryMonitor
{
    protected int $memoryLimit;

    protected int $warningThreshold;

    protected int $lastLoggedUsage = 0;

    public function __construct()
    {
        $this->memoryLimit = $this->parseMemoryLimit(ini_get('memory_limit'));
        $this->warningThreshold = (int) ($this->memoryLimit * 0.8);
    }

    /**
     * Check current memory usage and log warnings if necessary.
     */
    public function checkMemoryUsage(string $context = ''): array
    {
        $currentUsage = memory_get_usage(true);
        $peakUsage = memory_get_peak_usage(true);
        $percentUsed = ($currentUsage / $this->memoryLimit) * 100;

        $status = [
            'current_bytes' => $currentUsage,
            'current_mb' => round($currentUsage / 1024 / 1024, 2),
            'peak_bytes' => $peakUsage,
            'peak_mb' => round($peakUsage / 1024 / 1024, 2),
            'limit_mb' => round($this->memoryLimit / 1024 / 1024, 2),
            'percent_used' => round($percentUsed, 2),
            'warning' => $currentUsage > $this->warningThreshold,
        ];

        // Log warning if memory usage is high
        if ($currentUsage > $this->warningThreshold) {
            // Only log every 50MB increase to avoid spam
            if ($currentUsage - $this->lastLoggedUsage > 50 * 1024 * 1024) {
                Log::warning('High memory usage detected', array_merge([
                    'context' => $context,
                ], $status));
                $this->lastLoggedUsage = $currentUsage;
            }
        }

        return $status;
    }

    /**
     * Force garbage collection and return memory freed.
     */
    public function forceGarbageCollection(): int
    {
        $beforeGC = memory_get_usage(true);
        gc_collect_cycles();
        $afterGC = memory_get_usage(true);

        return $beforeGC - $afterGC;
    }

    /**
     * Parse memory limit string to bytes.
     */
    protected function parseMemoryLimit(string $memoryLimit): int
    {
        $memoryLimit = trim($memoryLimit);
        $last = strtolower(substr($memoryLimit, -1));
        $value = (int) substr($memoryLimit, 0, -1);

        switch ($last) {
            case 'g':
                $value *= 1024;
                // fallthrough
            case 'm':
                $value *= 1024;
                // fallthrough
            case 'k':
                $value *= 1024;
        }

        return $value;
    }

    /**
     * Get formatted memory usage string.
     */
    public function getFormattedUsage(): string
    {
        $current = memory_get_usage(true);
        $peak = memory_get_peak_usage(true);

        return sprintf(
            'Current: %s, Peak: %s, Limit: %s',
            $this->formatBytes($current),
            $this->formatBytes($peak),
            $this->formatBytes($this->memoryLimit)
        );
    }

    /**
     * Format bytes to human readable format.
     */
    protected function formatBytes(int $size, int $precision = 2): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];

        for ($i = 0; $size > 1024 && $i < count($units) - 1; $i++) {
            $size /= 1024;
        }

        return round($size, $precision).' '.$units[$i];
    }
}
