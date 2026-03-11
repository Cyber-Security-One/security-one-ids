<?php

return [
    /*
    |--------------------------------------------------------------------------
    | WAF Hub Connection
    |--------------------------------------------------------------------------
    */

    'waf_url' => env('WAF_URL', ''),
    'agent_token' => env('AGENT_TOKEN', ''),
    'agent_name' => env('AGENT_NAME', gethostname()),
    'install_token' => env('INSTALL_TOKEN', ''),

    /*
    |--------------------------------------------------------------------------
    | IDS/IPS Configuration
    |--------------------------------------------------------------------------
    */

    /**
     * Nginx Access Log Path
     */
    'nginx_log_path' => env('IDS_NGINX_LOG_PATH', '/var/log/nginx/access.log'),

    /**
     * Log Monitoring Settings
     */
    'log_monitor' => [
        'enabled' => env('IDS_LOG_MONITOR_ENABLED', true),
        'batch_size' => env('IDS_LOG_BATCH_SIZE', 100),
        'check_interval' => env('IDS_LOG_CHECK_INTERVAL', 5), // seconds
    ],

    /**
     * Queue Settings
     */
    'queue' => [
        'connection' => env('IDS_QUEUE_CONNECTION', 'database'),
        'name' => env('IDS_QUEUE_NAME', 'ids-processing'),
    ],

    /**
     * Detection Settings (placeholder for Phase 2)
     */
    'detection' => [
        'signature_enabled' => true,
        'anomaly_enabled' => true,
        'behavior_enabled' => true,
    ],

    /**
     * Blocking Settings
     */
    'blocking' => [
        'enabled' => env('IDS_BLOCKING_ENABLED', false),
        'mode' => env('IDS_BLOCKING_MODE', 'hybrid'), // 'waf', 'iptables', 'hybrid'
        'auto_unblock_after' => env('IDS_AUTO_UNBLOCK_AFTER', 3600), // seconds
        'whitelist' => array_filter(explode(',', env('IDS_IP_WHITELIST', ''))),
    ],

    /**
     * Alert Settings
     */
    'alerts' => [
        'email_enabled' => env('IDS_ALERT_EMAIL_ENABLED', false),
        'email_to' => env('IDS_ALERT_EMAIL_TO', 'admin@example.com'),
        'webhook_enabled' => env('IDS_ALERT_WEBHOOK_ENABLED', false),
        'webhook_url' => env('IDS_ALERT_WEBHOOK_URL'),
        'slack_enabled' => env('IDS_ALERT_SLACK_ENABLED', false),
        'slack_webhook_url' => env('IDS_ALERT_SLACK_WEBHOOK_URL'),
        'discord_enabled' => env('IDS_ALERT_DISCORD_ENABLED', false),
        'discord_webhook_url' => env('IDS_ALERT_DISCORD_WEBHOOK_URL'),
        'rate_limit' => env('IDS_ALERT_RATE_LIMIT', 10), // alerts per minute per IP/category
    ],

    /**
     * Anomaly Detection Thresholds
     */
    'anomaly' => [
        'rate_threshold' => env('IDS_RATE_THRESHOLD', 100), // requests per minute
        'max_request_size' => env('IDS_MAX_REQUEST_SIZE', 1048576), // 1MB
        'max_url_length' => env('IDS_MAX_URL_LENGTH', 2048),
        'business_hours_start' => env('IDS_BUSINESS_HOURS_START', 8),
        'business_hours_end' => env('IDS_BUSINESS_HOURS_END', 22),
    ],
];
