<?php

namespace App\Http\Middleware;

use App\Exceptions\MissingAgentTokenException;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class ValidateAgentToken
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $agentToken = config('ids.agent_token');

        if (app()->environment('production') && !trim((string) $agentToken)) {
            throw new MissingAgentTokenException();
        }

        $token = $request->input('token') ?? $request->header('X-Agent-Token') ?? $request->bearerToken();

        if (!$token || $token !== $agentToken) {
            throw new MissingAgentTokenException('Invalid or missing agent token.');
        }

        return $next($request);
    }
}
