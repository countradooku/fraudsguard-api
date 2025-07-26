<?php

namespace App\Services\FraudDetection\DataSources;

use App\Models\TorExitNode;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class TorExitNodeUpdater
{
    protected array $sources = [
        'torproject' => 'https://check.torproject.org/torbulkexitlist',
        'dan' => 'https://www.dan.me.uk/torlist/?exit',
    ];

    protected int $memoryLimit;

    public function __construct()
    {
        $memoryLimitString = ini_get('memory_limit');

        if ($memoryLimitString === '-1') {
            // Handle unlimited memory if needed, e.g., set a high default
            // For now, we'll just avoid calculation.
            // You might want to assign a large, but finite, number.
            $this->memoryLimit = PHP_INT_MAX;
        } else {
            $memoryInBytes = $this->convertShorthandToBytes($memoryLimitString);
            $this->memoryLimit = (int) ($memoryInBytes * 0.8);
        }
    }

    /**
     * Update Tor exit nodes from all sources.
     */
    public function updateAll(): array
    {
        ini_set('memory_limit', '256M');

        $results = [];
        $totalNodes = 0;

        // Mark all existing nodes as inactive
        DB::statement('UPDATE tor_exit_nodes SET is_active = false');

        foreach ($this->sources as $name => $url) {
            try {
                $count = $this->fetchAndProcessSource($name, $url);
                $results[$name] = [
                    'success' => true,
                    'count' => $count,
                ];
                $totalNodes += $count;

                gc_collect_cycles();

            } catch (\Exception $e) {
                $results[$name] = [
                    'success' => false,
                    'error' => $e->getMessage(),
                ];
                Log::error("Failed to fetch Tor nodes from {$name}", [
                    'error' => $e->getMessage(),
                ]);
            }
        }

        // Fetch detailed data from Onionoo API
        try {
            $count = $this->fetchOnionooData();
            $results['onionoo'] = [
                'success' => true,
                'count' => $count,
            ];
            $totalNodes += $count;
        } catch (\Exception $e) {
            $results['onionoo'] = [
                'success' => false,
                'error' => $e->getMessage(),
            ];
        }

        // Clean up old nodes
        $this->cleanupOldNodes();

        return [
            'sources' => $results,
            'total_nodes' => $totalNodes,
        ];
    }

    /**
     * Fetch and process nodes from a simple IP list source.
     */
    protected function fetchAndProcessSource(string $name, string $url): int
    {
        $tempFile = tempnam(sys_get_temp_dir(), "tor_nodes_{$name}_");
        $processedCount = 0;

        try {
            $response = Http::timeout(30)->sink($tempFile)->get($url);

            if (!$response->successful()) {
                throw new \Exception('HTTP request failed with status: ' . $response->status());
            }

            $handle = fopen($tempFile, 'r');
            if (!$handle) {
                throw new \Exception('Could not open temporary file');
            }

            $batch = [];
            $batchSize = 100;

            while (($line = fgets($handle)) !== false) {
                $ip = trim($line);

                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    $batch[] = [
                        'ip' => $ip,
                        'source' => $name,
                    ];

                    if (count($batch) >= $batchSize) {
                        $this->processNodeBatch($batch);
                        $processedCount += count($batch);
                        $batch = [];
                    }
                }
            }

            // Process remaining nodes
            if (!empty($batch)) {
                $this->processNodeBatch($batch);
                $processedCount += count($batch);
            }

            fclose($handle);

        } finally {
            @unlink($tempFile);
        }

        return $processedCount;
    }

    /**
     * Fetch detailed data from Onionoo API with pagination.
     */
    protected function fetchOnionooData(): int
    {
        $processedCount = 0;
        $offset = 0;
        $limit = 1000; // Process in smaller chunks

        do {
            try {
                $response = Http::timeout(30)->get('https://onionoo.torproject.org/details', [
                    'type' => 'relay',
                    'flag' => 'exit',
                    'fields' => 'nickname,fingerprint,exit_addresses,last_seen',
                    'offset' => $offset,
                    'limit' => $limit,
                ]);

                if (!$response->successful()) {
                    break;
                }

                $data = $response->json();
                $relays = $data['relays'] ?? [];

                if (empty($relays)) {
                    break;
                }

                $batch = [];
                foreach ($relays as $relay) {
                    foreach ($relay['exit_addresses'] ?? [] as $address) {
                        $ip = explode(':', $address)[0]; // Remove port if present
                        if (filter_var($ip, FILTER_VALIDATE_IP)) {
                            $batch[] = [
                                'ip' => $ip,
                                'node_id' => $relay['fingerprint'] ?? null,
                                'nickname' => $relay['nickname'] ?? null,
                                'last_seen' => $relay['last_seen'] ?? null,
                                'source' => 'onionoo',
                            ];
                        }
                    }
                }

                if (!empty($batch)) {
                    $this->processNodeBatch($batch);
                    $processedCount += count($batch);
                }

                $offset += $limit;

                // Force garbage collection every few iterations
                if ($offset % 5000 === 0) {
                    gc_collect_cycles();
                }

            } catch (\Exception $e) {
                Log::error('Error fetching Onionoo data', [
                    'offset' => $offset,
                    'error' => $e->getMessage(),
                ]);
                break;
            }

        } while (count($relays) === $limit); // Continue while we get full pages

        return $processedCount;
    }

    /**
     * Process a batch of nodes.
     */
    protected function processNodeBatch(array $nodes): void
    {
        if (empty($nodes)) {
            return;
        }

        $data = [];
        $now = now();

        foreach ($nodes as $node) {
            $ipVersion = filter_var($node['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 'v4' : 'v6';

            $data[] = [
                'ip_address' => $node['ip'],
                'ip_version' => $ipVersion,
                'node_id' => $node['node_id'] ?? null,
                'nickname' => $node['nickname'] ?? null,
                'is_active' => true,
                'risk_weight' => 90,
                'last_seen_at' => isset($node['last_seen'])
                    ? \Carbon\Carbon::parse($node['last_seen'])
                    : $now,
                'created_at' => $now,
                'updated_at' => $now,
            ];
        }

        TorExitNode::upsert(
            $data,
            ['ip_address'], // Unique key
            ['ip_version', 'node_id', 'nickname', 'is_active', 'last_seen_at', 'updated_at']
        );

        unset($data);
    }

    /**
     * Clean up old inactive nodes.
     */
    protected function cleanupOldNodes(): void
    {
        DB::statement('DELETE FROM tor_exit_nodes WHERE is_active = true AND last_seen_at < ?', [
            now()->subDays(30)
        ]);
    }

    /**
     * Converts a shorthand byte value string (e.g., 256M, 1G) to bytes.
     */
    private function convertShorthandToBytes(string $shorthand): int
    {
        $shorthand = strtolower(trim($shorthand));
        $value = (int) $shorthand;

        switch (substr($shorthand, -1)) {
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
}
