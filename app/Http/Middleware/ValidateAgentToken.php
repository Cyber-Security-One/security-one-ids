<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\App;
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
        if (App::environment('production') && trim((string) Config::get('ids.agent_token', '')) === '') {
            if (!App::isDownForMaintenance()) {
                \Illuminate\Support\Facades\Log::warning('AGENT_TOKEN must be set in production environment.');
                throw new HttpException(503, 'AGENT_TOKEN must be set in production environment.');
            }
        }

        return $next($request);
    }
}
