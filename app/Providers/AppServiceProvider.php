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
    public function boot(\Illuminate\Contracts\Foundation\Application $app, \App\Services\AgentTokenService $agentTokenService): void
    {
        // Only register CLI event listeners if we are running in the console
        if ($app->runningInConsole()) {
            // Log a warning universally for background CLI tasks rather than crashing them
            $app['events']->listen(\Illuminate\Queue\Events\WorkerStarting::class, function (\Illuminate\Queue\Events\WorkerStarting $event) use ($agentTokenService) {
                if ($agentTokenService->isMissingToken()) {
                    \Illuminate\Support\Facades\Log::warning('AGENT_TOKEN is missing in production. This may cause background WAF/IDS jobs to fail.');
                }
            });

            // Catch custom background IDS commands before they execute and log explicitly
            $app['events']->listen(\Illuminate\Console\Events\CommandStarting::class, function (\Illuminate\Console\Events\CommandStarting $event) use ($app, $agentTokenService) {
                if (!$app->environment('production')) {
                    return;
                }

                if ($agentTokenService->isMissingToken() && $event->command && str_starts_with($event->command, 'ids:')) {
                    \Illuminate\Support\Facades\Log::error("Cannot execute {$event->command}: AGENT_TOKEN must be set in production environment.");
                    // Exit cleanly to prevent the command from continuing without a token,
                    // without throwing an unhandled exception that dumps a stack trace.
                    throw new \App\Exceptions\MissingConsoleAgentTokenException("Cannot execute {$event->command}: AGENT_TOKEN must be set in production environment.");
                }
            });
        }
    }
}
