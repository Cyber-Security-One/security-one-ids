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
<<<<<<< HEAD
        // Only enforce token check during background processes that are explicitly critical.
        // E.g., block queue worker or schedule worker if misconfigured.
        if ($this->app->environment('production') && $this->app->runningInConsole() && trim(config('ids.agent_token', '')) === '') {
            if (!$this->app->isDownForMaintenance()) {
                if ($this->app->runningConsoleCommand('queue:work') || $this->app->runningConsoleCommand('schedule:run') || $this->app->runningConsoleCommand('schedule:work')) {
                    throw new \RuntimeException('AGENT_TOKEN must be set in production environment for background processes.');
                }
            }
        }
=======
        //
>>>>>>> 44fde90 (Fix SymfonyProcess instantiation in WafSyncService)
    }
}
