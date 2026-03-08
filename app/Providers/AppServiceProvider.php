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
    public function boot(
        \Illuminate\Contracts\Foundation\Application $app,
        \Illuminate\Contracts\Config\Repository $config,
        \Illuminate\Contracts\Events\Dispatcher $events
    ): void {
        if ($app->runningInConsole()) {
            $checkToken = function () use ($app, $config) {
                if ($app->environment('production') && trim((string) $config->get('ids.agent_token', '')) === '') {
                    if (!$app->isDownForMaintenance()) {
                        throw new \RuntimeException('AGENT_TOKEN must be set in production environment.');
                    }
                }
            };

            $events->listen(\Illuminate\Console\Events\CommandStarting::class, $checkToken);
            $events->listen(\Illuminate\Queue\Events\WorkerStarting::class, $checkToken);
        }
    }
}
