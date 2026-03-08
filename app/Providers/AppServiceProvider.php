<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use App\Exceptions\MissingAgentTokenException;
use Illuminate\Support\Facades\Log;

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
                // Catch queue workers universally
                $this->app['events']->listen(\Illuminate\Queue\Events\WorkerStarting::class, function () {
                    Log::warning('AGENT_TOKEN is missing in production. This may cause background WAF processes to fail.');
                });

                // Catch custom background IDS commands before they execute
                $this->app['events']->listen(\Illuminate\Console\Events\CommandStarting::class, function ($event) {
                    if ($event->command && str_starts_with($event->command, 'ids:')) {
                        throw new MissingAgentTokenException();
                    }
                });
            }
        }
    }
}
