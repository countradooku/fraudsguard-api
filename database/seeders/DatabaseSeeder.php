<?php

namespace Database\Seeders;

use App\Models\ASN;
use App\Models\DisposableEmailDomain;
use App\Models\KnownUserAgent;
use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        // Create demo user
        $demoUser = User::create([
            'name' => 'Demo User',
            'email' => 'demo@fraudguard.com',
            'email_verified_at' => now(),
            'password' => Hash::make('password'),
            'company_name' => 'Demo Company',
            'free_checks_remaining' => 100,
            'free_checks_reset_at' => now()->addMonth(),
        ]);

        // Create API key for demo user
        $apiKeyResult = \App\Models\ApiKey::generate($demoUser, 'Demo API Key');

        $this->command->info('Demo user created:');
        $this->command->info('Email: demo@fraudguard.com');
        $this->command->info('Password: password');
        $this->command->info('API Key: '.$apiKeyResult['key']);
        $this->command->info('API Secret: '.$apiKeyResult['secret']);

        // Seed disposable email domains
        $this->seedDisposableEmails();

        // Seed ASN data
        $this->seedASNData();

        // Seed known user agents
        $this->seedUserAgents();
    }

    /**
     * Seed disposable email domains.
     */
    protected function seedDisposableEmails(): void
    {
        $domains = [
            '10minutemail.com',
            'guerrillamail.com',
            'mailinator.com',
            'temp-mail.org',
            'throwawaymail.com',
            'yopmail.com',
            'fakeinbox.com',
            'trashmail.com',
            'maildrop.cc',
            'dispostable.com',
            'mintemail.com',
            'tempmail.net',
            'spamgourmet.com',
            'sharklasers.com',
            'guerrillamailblock.com',
            'spam4.me',
            'grr.la',
            'mailnesia.com',
            'tempmailaddress.com',
            'mt2015.com',
        ];

        foreach ($domains as $domain) {
            DisposableEmailDomain::create([
                'domain' => $domain,
                'source' => 'seed',
                'risk_weight' => 80,
                'is_active' => true,
                'verified_at' => now(),
            ]);
        }

        $this->command->info('Seeded '.count($domains).' disposable email domains');
    }

    /**
     * Seed ASN data.
     */
    protected function seedASNData(): void
    {
        $asns = [
            [
                'asn' => 15169,
                'name' => 'AS15169',
                'organization' => 'Google LLC',
                'country_code' => 'US',
                'type' => 'datacenter',
                'risk_weight' => 30,
                'is_hosting' => true,
            ],
            [
                'asn' => 16509,
                'name' => 'AS16509',
                'organization' => 'Amazon.com, Inc.',
                'country_code' => 'US',
                'type' => 'datacenter',
                'risk_weight' => 30,
                'is_hosting' => true,
            ],
            [
                'asn' => 13335,
                'name' => 'AS13335',
                'organization' => 'Cloudflare, Inc.',
                'country_code' => 'US',
                'type' => 'datacenter',
                'risk_weight' => 25,
                'is_hosting' => true,
            ],
            [
                'asn' => 8075,
                'name' => 'AS8075',
                'organization' => 'Microsoft Corporation',
                'country_code' => 'US',
                'type' => 'datacenter',
                'risk_weight' => 30,
                'is_hosting' => true,
            ],
            [
                'asn' => 14061,
                'name' => 'AS14061',
                'organization' => 'DigitalOcean, LLC',
                'country_code' => 'US',
                'type' => 'datacenter',
                'risk_weight' => 40,
                'is_hosting' => true,
            ],
            [
                'asn' => 7922,
                'name' => 'AS7922',
                'organization' => 'Comcast Cable Communications, LLC',
                'country_code' => 'US',
                'type' => 'residential',
                'risk_weight' => 0,
                'is_hosting' => false,
            ],
            [
                'asn' => 701,
                'name' => 'AS701',
                'organization' => 'Verizon Business',
                'country_code' => 'US',
                'type' => 'residential',
                'risk_weight' => 0,
                'is_hosting' => false,
            ],
        ];

        foreach ($asns as $asn) {
            ASN::create(array_merge($asn, [
                'verified_at' => now(),
            ]));
        }

        $this->command->info('Seeded '.count($asns).' ASN records');
    }

    /**
     * Seed known user agents.
     */
    protected function seedUserAgents(): void
    {
        $userAgents = [
            [
                'user_agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
                'type' => 'bot',
                'name' => 'Googlebot',
                'version' => '2.1',
                'risk_weight' => 50,
            ],
            [
                'user_agent' => 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
                'type' => 'bot',
                'name' => 'Bingbot',
                'version' => '2.0',
                'risk_weight' => 50,
            ],
            [
                'user_agent' => 'curl/7.64.1',
                'type' => 'bot',
                'name' => 'cURL',
                'version' => '7.64.1',
                'risk_weight' => 70,
            ],
            [
                'user_agent' => 'PostmanRuntime/7.26.8',
                'type' => 'bot',
                'name' => 'Postman',
                'version' => '7.26.8',
                'risk_weight' => 60,
            ],
            [
                'user_agent' => 'python-requests/2.25.1',
                'type' => 'bot',
                'name' => 'Python Requests',
                'version' => '2.25.1',
                'risk_weight' => 70,
            ],
            [
                'user_agent' => 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)',
                'type' => 'browser',
                'name' => 'Internet Explorer',
                'version' => '6.0',
                'risk_weight' => 80,
                'is_outdated' => true,
                'eol_date' => '2014-04-08',
            ],
        ];

        foreach ($userAgents as $ua) {
            $ua['user_agent_hash'] = hash('sha256', $ua['user_agent']);
            KnownUserAgent::create($ua);
        }

        $this->command->info('Seeded '.count($userAgents).' known user agents');
    }
}
