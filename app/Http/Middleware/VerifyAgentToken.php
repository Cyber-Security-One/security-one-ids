<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class VerifyAgentToken
{
    public function handle(Request $request, Closure $next)
    {
        $token = $request->input('token');
        if ($token === null || $token === '') {
            $token = $request->header('X-Agent-Token');
        }
        if ($token === null || $token === '') {
            $token = $request->bearerToken();
        }

        $agentToken = (string) config('ids.agent_token', env('AGENT_TOKEN'));

        // To prevent information leakage (e.g., revealing via different response times
        // or codes that the system is misconfigured), we enforce a generic 401 response
        // for both missing configuration and invalid tokens.
        if (!is_scalar($token)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $token = (string) $token;
        $configured = $agentToken !== '';
        $expectedSeed = $configured ? $agentToken : str_repeat("\0", 32);

        $isValid = $configured
            && $token !== ''
            && hash_equals(
                hash('sha256', $expectedSeed, true),
                hash('sha256', $token, true)
            );

        if (!$isValid) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $next($request);
    }
}
