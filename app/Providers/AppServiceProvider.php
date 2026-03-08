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
        $token = config('ids.agent_token');
        if (app()->environment('production') && ($token === null || $token === '') && !app()->runningInConsole()) {
            throw new \RuntimeException('AGENT_TOKEN must be set in production environment.');
        }
    }
}
