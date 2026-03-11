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
        $normalizedToken = is_string($token) ? trim($token) : $token;

        if ($app->environment('production') && empty($normalizedToken)) {
            // Only enforce token check during background processes that are explicitly critical.
            // E.g., block queue worker or schedule worker if misconfigured.
            if (!$this->app->isDownForMaintenance()) {
                if ($this->app->runningConsoleCommand('queue:work') || $this->app->runningConsoleCommand('schedule:run') || $this->app->runningConsoleCommand('schedule:work')) {
                    throw new \RuntimeException('AGENT_TOKEN must be set in production environment for background processes.');
                }
            } else {
                $logger->warning('AGENT_TOKEN is empty in production environment during console command. This may lead to an insecure configuration cache.');
            }
        }
            }
        }
    }
}