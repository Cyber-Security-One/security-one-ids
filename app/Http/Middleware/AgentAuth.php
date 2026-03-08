<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class AgentAuth
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->bearerToken()
            ?? $request->header('X-Agent-Token')
            ?? $request->input('token');

        $agentToken = config('ids.agent_token', env('AGENT_TOKEN', ''));

        if (!is_string($token) || !is_string($agentToken)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        if ($token === '' || $agentToken === '' || strlen($token) > 256 || strlen($token) !== strlen($agentToken) || !hash_equals($agentToken, $token)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $next($request);
    }
}
