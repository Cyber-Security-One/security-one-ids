<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;

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
        $this->ensureAgentTokenConfigured();
    }

    /**
     * Validates that the AGENT_TOKEN is properly configured in production environments.
     * Throws an exception for web requests or logs a warning for CLI commands.
     */
    private function ensureAgentTokenConfigured(): void
    {
        if ($this->app->environment('production') && trim((string) config('ids.agent_token', '')) === '') {
            if (!$this->app->runningInConsole()) {
                throw new \RuntimeException('AGENT_TOKEN must be set in production environment.');
            }

            \Illuminate\Support\Facades\Log::warning('AGENT_TOKEN is empty in production environment during console command. This may lead to an insecure configuration cache.');
        }
    }
}
