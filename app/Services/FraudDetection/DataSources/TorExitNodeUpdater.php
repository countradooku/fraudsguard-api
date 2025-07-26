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
        'onionoo' => 'https://onionoo.torproject.org/details?type=relay&flag=exit',
    ];

    /**
     * Update Tor exit nodes from all sources.
     */
    public function updateAll(): array
    {
        $results = [];
        $allNodes = [];

        foreach ($this->sources as $name => $url) {
            try {
                $nodes = $this->fetchFromSource($name, $url);
                $results[$name] = [
                    'success' => true,
                    'count' => count($nodes),
                ];
                $allNodes = array_merge($allNodes, $nodes);
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

        // Remove duplicates by IP
        $uniqueNodes = $this->deduplicateNodes($allNodes);

        // Update database
        $this->updateDatabase($uniqueNodes);

        return [
            'sources' => $results,
            'total_nodes' => count($uniqueNodes),
        ];
    }

    /**
     * Fetch nodes from a specific source.
     */
    protected function fetchFromSource(string $name, string $url): array
    {
        $response = Http::timeout(30)->get($url);

        if (! $response->successful()) {
            throw new \Exception('HTTP request failed with status: '.$response->status());
        }

        switch ($name) {
            case 'torproject':
                return $this->parseTorProjectList($response->body());
            case 'dan':
                return $this->parseDanList($response->body());
            case 'onionoo':
                return $this->parseOnionooData($response->json());
            default:
                return [];
        }
    }

    /**
     * Parse TorProject exit list format.
     */
    protected function parseTorProjectList(string $content): array
    {
        $nodes = [];
        $lines = explode("\n", $content);

        foreach ($lines as $line) {
            $ip = trim($line);
            if ($this->isValidIP($ip)) {
                $nodes[] = [
                    'ip' => $ip,
                    'source' => 'torproject',
                ];
            }
        }

        return $nodes;
    }

    /**
     * Parse dan.me.uk list format.
     */
    protected function parseDanList(string $content): array
    {
        $nodes = [];
        $lines = explode("\n", $content);

        foreach ($lines as $line) {
            $ip = trim($line);
            if ($this->isValidIP($ip)) {
                $nodes[] = [
                    'ip' => $ip,
                    'source' => 'dan',
                ];
            }
        }

        return $nodes;
    }

    /**
     * Parse Onionoo API data.
     */
    protected function parseOnionooData(array $data): array
    {
        $nodes = [];

        foreach ($data['relays'] ?? [] as $relay) {
            foreach ($relay['exit_addresses'] ?? [] as $address) {
                $ip = explode(':', $address)[0]; // Remove port if present
                if ($this->isValidIP($ip)) {
                    $nodes[] = [
                        'ip' => $ip,
                        'node_id' => $relay['fingerprint'] ?? null,
                        'nickname' => $relay['nickname'] ?? null,
                        'last_seen' => $relay['last_seen'] ?? null,
                        'source' => 'onionoo',
                    ];
                }
            }
        }

        return $nodes;
    }

    /**
     * Validate IP address.
     */
    protected function isValidIP(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * Remove duplicate nodes by IP.
     */
    protected function deduplicateNodes(array $nodes): array
    {
        $unique = [];
        $seen = [];

        foreach ($nodes as $node) {
            if (! isset($seen[$node['ip']])) {
                $unique[] = $node;
                $seen[$node['ip']] = true;
            } elseif (! empty($node['node_id']) || ! empty($node['nickname'])) {
                // Prefer entries with more metadata
                $index = array_search($node['ip'], array_column($unique, 'ip'));
                if ($index !== false && empty($unique[$index]['node_id'])) {
                    $unique[$index] = $node;
                }
            }
        }

        return $unique;
    }

    /**
     * Update database with fetched nodes.
     */
    protected function updateDatabase(array $nodes): void
    {
        DB::transaction(function () use ($nodes) {
            // Mark all existing nodes as inactive
            TorExitNode::query()->update(['is_active' => false]);

            // Batch upsert nodes
            $chunks = array_chunk($nodes, 500);

            foreach ($chunks as $chunk) {
                $data = [];

                foreach ($chunk as $node) {
                    $ipVersion = filter_var($node['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 'v4' : 'v6';

                    $data[] = [
                        'ip_address' => $node['ip'],
                        'ip_version' => $ipVersion,
                        'node_id' => $node['node_id'] ?? null,
                        'nickname' => $node['nickname'] ?? null,
                        'is_active' => true,
                        'risk_weight' => 90, // High risk for Tor exit nodes
                        'last_seen_at' => isset($node['last_seen'])
                            ? \Carbon\Carbon::parse($node['last_seen'])
                            : now(),
                        'created_at' => now(),
                        'updated_at' => now(),
                    ];
                }

                TorExitNode::upsert(
                    $data,
                    ['ip_address'], // Unique key
                    ['ip_version', 'node_id', 'nickname', 'is_active', 'last_seen_at', 'updated_at']
                );
            }

            // Remove nodes not seen in 30 days
            TorExitNode::where('is_active', false)
                ->where('last_seen_at', '<', now()->subDays(30))
                ->delete();
        });
    }
}
