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
        // Prioritize non-empty tokens. If one is empty, fallback to the next.
        $token = $request->bearerToken();
        if ($token === null || $token === '') {
            $token = $request->header('X-Agent-Token');
        }
        if ($token === null || $token === '') {
            $token = $request->input('token');
        }

        $agentTokenEnv = env('AGENT_TOKEN');
        // If env('AGENT_TOKEN') is explicitly set to an empty string, it won't be strictly null,
        // so we need to fallback to config if it's strictly empty or null,
        // while preserving '0' which is not strictly empty.
        $agentToken = (string) ($agentTokenEnv !== null && $agentTokenEnv !== '' ? $agentTokenEnv : config('ids.agent_token', ''));

        if ($agentToken === '') {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        if (!is_scalar($token)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $token = (string) $token;

        if ($token === '' || strlen($token) > 256 || strlen($token) !== strlen($agentToken) || !hash_equals($agentToken, $token)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $next($request);
    }
}
