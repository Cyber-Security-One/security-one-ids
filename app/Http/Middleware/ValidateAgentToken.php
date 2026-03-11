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
        if (app()->environment('production') && (config('ids.agent_token') === null || trim((string) config('ids.agent_token')) === '')) {
            throw new MissingAgentTokenException();
        }

        return $next($request);
    }
}
