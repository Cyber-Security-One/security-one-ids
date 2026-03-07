<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class VerifyAgentToken
{
    public function handle(Request $request, Closure $next)
    {
        $token = (string) ($request->input('token') ?? $request->header('X-Agent-Token') ?? $request->bearerToken());
        $agentToken = (string) config('ids.agent_token');

        // To prevent information leakage (e.g., revealing via different response times
        // or codes that the system is misconfigured), we enforce a generic 401 response
        // for both missing configuration and invalid tokens.
        // We also check length to ensure hash_equals does not leak timing info based on length.
        if ($agentToken === '' || strlen($agentToken) !== strlen($token) || !hash_equals($agentToken, $token)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $next($request);
    }
}
