<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use RuntimeException;

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
    public function boot(): void
    {
// Only enforce token check during background processes that are explicitly critical.
        // E.g., block queue worker or schedule worker if misconfigured.
        $this->ensureAgentTokenConfigured();
    }

    /**
     * Validates that the AGENT_TOKEN is properly configured in production environments.
     * Throws an exception for web requests and critical background processes, logs a warning otherwise.
     */
    private function ensureAgentTokenConfigured(): void
    {
        if ($this->app->environment('production') && trim((string) config('ids.agent_token', '')) === '') {
            if (!$this->app->runningInConsole()) {
                throw new RuntimeException('AGENT_TOKEN must be set in production environment.');
            }

            // Block critical background processes that require the token.
            if ($this->app->isDownForMaintenance() || !$this->app->runningConsoleCommand('queue:work') && !$this->app->runningConsoleCommand('schedule:run') && !$this->app->runningConsoleCommand('schedule:work')) {
                \Illuminate\Support\Facades\Log::warning('AGENT_TOKEN is empty in production environment during console command. This may lead to an insecure configuration cache.');
            } else {
                throw new \RuntimeException('AGENT_TOKEN must be set in production environment for background processes.');
            }
        }
    }
        }
    }
}