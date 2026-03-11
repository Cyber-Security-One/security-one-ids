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
        $token = $request->bearerToken();
        if (is_string($token)) {
            $token = trim($token);
        }

        if ($token === null || $token === '') {
            $token = $request->header('X-Agent-Token');
            if (is_string($token)) {
                $token = trim($token);
            }
        }

        if ($token === null || $token === '') {
            $token = $request->input('token');
            if (is_string($token)) {
                $token = trim($token);
            }
        }

        $agentTokenEnv = env('AGENT_TOKEN');
        // Fallback to config ONLY if the environment variable is strictly null (missing) or explicitly empty string (default fallback for env() without value).
        // We preserve '0' which is not strictly empty.
        $agentToken = (string) ($agentTokenEnv !== null && $agentTokenEnv !== '' ? $agentTokenEnv : (config('ids.agent_token') ?? ''));

        if ($agentToken === '') {
            return response()->json(['error' => 'Server misconfiguration: AGENT_TOKEN is not set'], 503);
        }

        if (!is_scalar($token)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $token = (string) $token;

        if ($token === '' || strlen($token) !== strlen($agentToken) || !hash_equals($agentToken, $token)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $next($request);
    }
}
