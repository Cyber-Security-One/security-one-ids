<?php

namespace App\Services;

class AgentTokenService
{
    /**
     * Determine if the application is missing the required agent token in production.
     */
    public function isMissingToken(): bool
    {
        return app()->environment('production') && trim((string) config('ids.agent_token', '')) === '';
    }
}
