<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Fraud Detection Configuration
    |--------------------------------------------------------------------------
    */

    // Hashing configuration
    'hashing' => [
        'algorithm' => 'sha256',
        'key' => env('FRAUD_DETECTION_HASH_KEY', 'default-hash-key'),
    ],

    // Encryption key for sensitive data
    'encryption_key' => env('FRAUD_DETECTION_ENCRYPTION_KEY'),

    // Free tier configuration
    'free_tier_limit' => 100, // checks per month
    'free_tier_rate_limit' => 10, // requests per hour

    // Rate limits per plan (requests per hour)
    'rate_limits' => [
        'free' => env('API_RATE_LIMIT_FREE', 100),
        'basic' => env('API_RATE_LIMIT_BASIC', 1000),
        'pro' => env('API_RATE_LIMIT_PRO', 10000),
        'enterprise' => env('API_RATE_LIMIT_ENTERPRISE', 100000),
    ],

    // Overage pricing (per request after limit)
    'overage_pricing' => [
        'basic' => 0.01, // $0.01 per request
        'pro' => 0.005, // $0.005 per request
        'enterprise' => 0.001, // $0.001 per request
    ],

    // Risk score thresholds
    'risk_thresholds' => [
        'low' => 30,
        'medium' => 50,
        'high' => 80,
        'critical' => 100,
    ],

    // Decision thresholds
    'decision_thresholds' => [
        'auto_allow' => 30,
        'manual_review' => 50,
        'auto_block' => 80,
    ],

    // Feature flags
    'features' => [
        'tor_check' => env('FEATURE_TOR_CHECK', true),
        'vpn_check' => env('FEATURE_VPN_CHECK', true),
        'email_validation' => env('FEATURE_EMAIL_VALIDATION', true),
        'credit_card_check' => env('FEATURE_CREDIT_CARD_CHECK', true),
        'phone_check' => env('FEATURE_PHONE_CHECK', true),
        'geolocation_check' => env('FEATURE_GEOLOCATION_CHECK', true),
        'user_agent_check' => env('FEATURE_USER_AGENT_CHECK', true),
        'velocity_check' => env('FEATURE_VELOCITY_CHECK', true),
    ],

    // External API configuration
    'external_apis' => [
        'ipapi' => [
            'enabled' => true,
            'key' => env('IPAPI_KEY'),
            'timeout' => 3,
        ],
        'emailrep' => [
            'enabled' => false,
            'key' => env('EMAILREP_KEY'),
            'timeout' => 3,
        ],
        'spamhaus' => [
            'enabled' => false,
            'key' => env('SPAMHAUS_KEY'),
            'timeout' => 3,
        ],
    ],

    // Data source update schedules (cron expressions)
    'update_schedules' => [
        'tor_exit_nodes' => '0 */6 * * *', // Every 6 hours
        'disposable_emails' => '0 0 * * *', // Daily at midnight
        'asn_database' => '0 0 * * 0', // Weekly on Sunday
        'user_agents' => '0 0 1 * *', // Monthly on the 1st
    ],

    // Cache TTL (in seconds)
    'cache_ttl' => [
        'blacklist_check' => 300, // 5 minutes
        'disposable_domain' => 3600, // 1 hour
        'tor_node' => 3600, // 1 hour
        'asn_info' => 3600, // 1 hour
        'ip_geolocation' => 86400, // 24 hours
    ],

    // Webhook configuration
    'webhooks' => [
        'enabled' => true,
        'timeout' => 10,
        'retry_times' => 3,
        'retry_delay' => 60, // seconds
        'events' => [
            'fraud_check.completed',
            'fraud_check.high_risk',
            'fraud_check.blocked',
        ],
    ],

    // Logging configuration
    'logging' => [
        'enabled' => true,
        'channel' => 'fraud-detection',
        'level' => 'info',
        'sensitive_fields' => [
            'email',
            'ip',
            'credit_card',
            'phone',
        ],
    ],

    // Security settings
    'security_email' => env('FRAUD_DETECTION_SECURITY_EMAIL', 'security@fraudguard.com'),

    // Performance settings
    'performance' => [
        'max_processing_time' => 5000, // milliseconds
        'parallel_checks' => true,
        'queue_checks' => false, // Set to true for async processing
    ],

    // Data retention (in days)
    'data_retention' => [
        'fraud_checks' => 365, // 1 year
        'api_usage' => 90, // 3 months
        'blacklist_entries' => 180, // 6 months
    ],
];
