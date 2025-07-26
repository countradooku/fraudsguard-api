<?php

namespace App\Console\Commands;

use App\Models\ASN;
use Carbon\Carbon;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class UpdateASNDatabaseCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'fraud:update-asn
                            {--force : Force update even if recently updated}
                            {--source=ripe : Update from specific source (ripe, maxmind, ipinfo)}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Update the ASN (Autonomous System Number) database';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $this->info('Starting ASN database update...');

        // Check if recently updated (unless forced)
        if (! $this->option('force')) {
            $lastUpdate = ASN::max('updated_at');
            if ($lastUpdate && Carbon::parse($lastUpdate)->diffInDays(now()) < 7) {
                $this->info('ASN database was recently updated. Use --force to update anyway.');

                return 0;
            }
        }

        try {
            $source = $this->option('source');
            $asnData = [];

            switch ($source) {
                case 'ripe':
                    $asnData = $this->fetchFromRIPE();
                    break;
                case 'maxmind':
                    $asnData = $this->fetchFromMaxMind();
                    break;
                case 'ipinfo':
                    $asnData = $this->fetchFromIPInfo();
                    break;
                default:
                    $this->error('Invalid source specified');

                    return 1;
            }

            if (empty($asnData)) {
                $this->error('No ASN data fetched from source');

                return 1;
            }

            $this->info('Fetched '.count($asnData).' ASN records');

            // Update database
            $this->updateDatabase($asnData);

            $this->info('ASN database update completed successfully');

            // Log the update
            Log::info('ASN database updated', [
                'source' => $source,
                'count' => count($asnData),
                'timestamp' => now(),
            ]);

            return 0;

        } catch (\Exception $e) {
            $this->error('Error updating ASN database: '.$e->getMessage());
            Log::error('ASN update failed', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            return 1;
        }
    }

    /**
     * Fetch ASN data from RIPE NCC
     */
    protected function fetchFromRIPE(): array
    {
        $this->info('Fetching from RIPE NCC...');
        $asnData = [];

        try {
            // RIPE provides data in various formats
            // This is a simplified example - in production you'd use their bulk data access
            $response = Http::timeout(60)->get('https://ftp.ripe.net/ripe/asnames/asn.txt');

            if ($response->successful()) {
                $lines = explode("\n", $response->body());

                foreach ($lines as $line) {
                    if (empty($line) || str_starts_with($line, '#')) {
                        continue;
                    }

                    // Format: ASN, Country, Organization
                    if (preg_match('/^(\d+)\s+(\w{2})\s+(.+)$/', $line, $matches)) {
                        $asn = (int) $matches[1];
                        $country = $matches[2];
                        $organization = trim($matches[3]);

                        $asnData[$asn] = [
                            'asn' => $asn,
                            'name' => "AS{$asn}",
                            'organization' => $organization,
                            'country_code' => $country,
                            'type' => $this->classifyASN($organization),
                        ];
                    }
                }
            }
        } catch (\Exception $e) {
            $this->warn('Failed to fetch from RIPE: '.$e->getMessage());
        }

        return $asnData;
    }

    /**
     * Fetch ASN data from MaxMind (requires license)
     */
    protected function fetchFromMaxMind(): array
    {
        $this->info('Fetching from MaxMind...');

        // MaxMind requires a license key
        $licenseKey = config('services.maxmind.license_key');
        if (! $licenseKey) {
            $this->error('MaxMind license key not configured');

            return [];
        }

        // Download GeoLite2 ASN database
        // Implementation would download and parse the MaxMind database

        return [];
    }

    /**
     * Fetch ASN data from IPInfo
     */
    protected function fetchFromIPInfo(): array
    {
        $this->info('Fetching from IPInfo...');

        // IPInfo provides a free tier with limited requests
        $token = config('services.ipinfo.token');
        if (! $token) {
            $this->error('IPInfo token not configured');

            return [];
        }

        // This would fetch ASN data from IPInfo's API
        // Note: Their bulk data requires a paid plan

        return [];
    }

    /**
     * Classify ASN type based on organization name
     */
    protected function classifyASN(string $organization): string
    {
        $org = strtolower($organization);

        // Hosting/Cloud providers
        $hostingKeywords = [
            'hosting', 'cloud', 'server', 'vps', 'dedicated', 'colocation',
            'datacenter', 'data center', 'amazon', 'google', 'microsoft',
            'digitalocean', 'linode', 'vultr', 'ovh', 'hetzner',
        ];

        foreach ($hostingKeywords as $keyword) {
            if (str_contains($org, $keyword)) {
                return 'datacenter';
            }
        }

        // ISPs/Telecom
        $ispKeywords = [
            'telecom', 'communications', 'internet', 'broadband', 'cable',
            'dsl', 'fiber', 'wireless', 'mobile', 'cellular', 'isp',
        ];

        foreach ($ispKeywords as $keyword) {
            if (str_contains($org, $keyword)) {
                return 'residential';
            }
        }

        // Education
        if (str_contains($org, 'university') || str_contains($org, 'college') ||
            str_contains($org, 'education') || str_contains($org, 'academic')) {
            return 'education';
        }

        // Government
        if (str_contains($org, 'government') || str_contains($org, 'military') ||
            str_contains($org, 'defense') || str_contains($org, 'federal')) {
            return 'government';
        }

        return 'unknown';
    }

    /**
     * Update database with fetched ASN data
     *
     * @throws \Throwable
     */
    protected function updateDatabase(array $asnData): void
    {
        $this->info('Updating database...');
        $bar = $this->output->createProgressBar(count($asnData));
        $bar->start();

        DB::beginTransaction();

        try {
            // Process in chunks
            $chunks = array_chunk($asnData, 1000, true);

            foreach ($chunks as $chunk) {
                $data = [];

                foreach ($chunk as $asn => $info) {
                    $data[] = [
                        'asn' => $info['asn'],
                        'name' => $info['name'] ?? "AS{$info['asn']}",
                        'organization' => $info['organization'] ?? 'Unknown',
                        'country_code' => $info['country_code'] ?? null,
                        'type' => $info['type'] ?? 'unknown',
                        'risk_weight' => $this->calculateRiskWeight($info),
                        'is_hosting' => $info['type'] === 'datacenter',
                        'is_vpn' => $info['is_vpn'] ?? false,
                        'is_proxy' => $info['is_proxy'] ?? false,
                        'verified_at' => now(),
                        'created_at' => now(),
                        'updated_at' => now(),
                    ];
                }

                // Upsert ASN records
                ASN::upsert(
                    $data,
                    ['asn'], // Unique key
                    ['name', 'organization', 'country_code', 'type', 'risk_weight',
                        'is_hosting', 'is_vpn', 'is_proxy', 'verified_at', 'updated_at']
                );

                $bar->advance(count($chunk));
            }

            DB::commit();
            $bar->finish();
            $this->newLine();

        } catch (\Exception $e) {
            DB::rollBack();
            throw $e;
        } catch (\Throwable $e) {
        }
    }

    /**
     * Calculate risk weight for ASN
     */
    protected function calculateRiskWeight(array $asnInfo): int
    {
        $weight = 0;

        // Datacenter ASNs have higher risk
        if (($asnInfo['type'] ?? '') === 'datacenter') {
            $weight += 30;
        }

        // Known VPN/Proxy providers
        if ($asnInfo['is_vpn'] ?? false) {
            $weight += 40;
        }

        if ($asnInfo['is_proxy'] ?? false) {
            $weight += 40;
        }

        // Certain countries might have different risk profiles
        // This is a simplified example - adjust based on your needs
        $highRiskCountries = ['XX', 'YY']; // Example country codes
        if (in_array($asnInfo['country_code'] ?? '', $highRiskCountries)) {
            $weight += 20;
        }

        return min($weight, 100);
    }
}
