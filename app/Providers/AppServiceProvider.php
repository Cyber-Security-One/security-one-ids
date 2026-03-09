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
        if (app()->environment('production') && trim((string) config('ids.agent_token', '')) === '') {
            // Only register CLI event listeners if we are running in the console
            if ($this->app->runningInConsole()) {
                // Log an error universally for background CLI tasks rather than crashing them
                $this->app['events']->listen(\Illuminate\Queue\Events\WorkerStarting::class, function (\Illuminate\Queue\Events\WorkerStarting $event) {
                    \Illuminate\Support\Facades\Log::error('AGENT_TOKEN is missing in production. This may cause background WAF/IDS jobs to fail.');
                });

                // Catch custom background IDS commands before they execute and log explicitly
                $this->app['events']->listen(\Illuminate\Console\Events\CommandStarting::class, function (\Illuminate\Console\Events\CommandStarting $event) {
                    if (!app()->environment('production')) {
                        return;
                    }

                    if ($event->command && (str_starts_with($event->command, 'ids:') || str_starts_with($event->command, 'waf:') || str_starts_with($event->command, 'desktop:'))) {
                        throw new \App\Exceptions\MissingAgentTokenException();
                    }
                });
            }
        }
    }
}
