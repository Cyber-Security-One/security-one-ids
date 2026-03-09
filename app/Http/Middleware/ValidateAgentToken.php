<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use App\Exceptions\MissingAgentTokenException;
use App\Services\AgentTokenService;
use Illuminate\Support\Facades\Log;

class ValidateAgentToken
{
    public function __construct(protected AgentTokenService $agentTokenService)
    {
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if ($this->agentTokenService->isMissingToken()) {
            if (!app()->runningInConsole()) {
                throw new MissingAgentTokenException();
            } else {
                Log::warning('AGENT_TOKEN is missing in production. This may cause background WAF processes to fail.');
            }
        }

        return $next($request);
    }
}
