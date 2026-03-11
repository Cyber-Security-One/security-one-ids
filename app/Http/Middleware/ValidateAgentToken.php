<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;

class ValidateAgentToken
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Skip health check routes to ensure probes pass even if misconfigured
        if (in_array($request->path(), ['up', 'health'], true)) {
            return $next($request);
        }

        if (app()->isProduction() && trim((string) config('ids.agent_token', '')) === '') {
            throw new HttpException(503, 'Service Unavailable: AGENT_TOKEN must be explicitly configured in production.');
        }

        return $next($request);
    }
}
