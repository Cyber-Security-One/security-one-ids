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
        if ($this->app->environment('production') && trim((string) config('ids.agent_token', '')) === '') {
            // Only throw an exception if we are specifically handling web requests
            // to avoid breaking deployment pipelines (like config:cache, key:generate, package:discover, etc.)
            // We rely on runningInConsole() to detect CLI SAPIs (like the queue worker or artisan setup).
            if (!$this->app->runningInConsole()) {
                throw new \RuntimeException('AGENT_TOKEN must be set in production environment.');
            } else {
                \Illuminate\Support\Facades\Log::warning('AGENT_TOKEN is empty in production environment during console command. This may lead to an insecure configuration cache.');
            }
        }
    }
}
