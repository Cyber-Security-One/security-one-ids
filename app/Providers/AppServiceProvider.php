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
        // Skip validation during initial setup commands or testing that run in production
        // before the env file is fully populated.
        $command = $_SERVER['argv'][1] ?? null;
        if (in_array($command, ['key:generate', 'package:discover', 'test', 'env'])) {
            return;
        }

        if (app()->environment('production') && trim((string) config('ids.agent_token', '')) === '') {
            throw new \RuntimeException('AGENT_TOKEN must be set in production environment.');
        }
    }
}
