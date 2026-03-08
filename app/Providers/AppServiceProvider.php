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
            // We register an event listener to catch queue workers universally and ensure
            // the token is validated when they start, ensuring no runtime errors later.
            $this->app['events']->listen(\Illuminate\Queue\Events\WorkerStarting::class, function () {
                throw new \RuntimeException('AGENT_TOKEN must be set in production environment.');
            });

            // For custom IDS commands that act as background processes, we validate before they execute
            // using the CommandStarting event rather than fragile parsing of $_SERVER['argv'].
            $this->app['events']->listen(\Illuminate\Console\Events\CommandStarting::class, function ($event) {
                if ($event->command && str_starts_with($event->command, 'ids:')) {
                    throw new \RuntimeException('AGENT_TOKEN must be set in production environment.');
                }
            });

            // For web requests, we validate and ensure we are not in maintenance mode.
            // This prevents unexpected failures during deployment or maintenance mode.
            if (!app()->runningInConsole() && !app()->isDownForMaintenance()) {
                throw new \RuntimeException('AGENT_TOKEN must be set in production environment.');
            }
        }
    }
}
