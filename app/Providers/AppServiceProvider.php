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
        if (!$this->app->runningInConsole() && !$this->app->runningUnitTests()) {
            $agentTokenEnv = env('AGENT_TOKEN');
            $agentToken = (string) ($agentTokenEnv !== null && $agentTokenEnv !== '' ? $agentTokenEnv : config('ids.agent_token', ''));

            if ($agentToken === '') {
                throw new \RuntimeException('AGENT_TOKEN is not configured. The security agent cannot start.');
            }
        }
    }
}
