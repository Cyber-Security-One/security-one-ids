<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Psr\Log\LoggerInterface;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(Application $app, LoggerInterface $logger, ConfigRepository $config): void
    {
        $token = $config->get('ids.agent_token', '');
        $isValidToken = is_string($token) && trim($token) !== '';

        if ($app->environment('production') && !$isValidToken) {
            // Only throw an exception if we are specifically handling web requests
            // to avoid breaking deployment pipelines (like config:cache, key:generate, package:discover, etc.)
            // We rely on runningInConsole() to detect CLI SAPIs (like the queue worker or artisan setup).
            if (!$app->runningInConsole()) {
                throw new \RuntimeException('AGENT_TOKEN must be set in production environment.');
            } else {
                $logger->warning('AGENT_TOKEN is empty in production environment during console command. This may lead to an insecure configuration cache.');
            }
        }
    }
}
