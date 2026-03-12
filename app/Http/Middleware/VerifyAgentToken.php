<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class VerifyAgentToken
{
    public function handle(Request $request, Closure $next)
    {
        $token = $request->bearerToken();
        if ($token === null || $token === '') {
            $token = $request->header('X-Agent-Token');
        }
        if ($token === null || $token === '') {
            $token = $request->input('token');
        }
        $agentToken = (string) config('ids.agent_token', '');

        // To prevent information leakage (e.g., revealing via different response times
        // or codes that the system is misconfigured), we enforce a generic 401 response
        // for both missing configuration and invalid tokens.
        if (!is_string($token)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $configured = $agentToken !== '';

        $expectedSeed = $configured ? $agentToken : str_repeat("\0", 32);
        $tokenForHash = $token !== '' ? $token : str_repeat("\0", 32);

        $expectedHash = hash('sha256', $expectedSeed, true);
        $actualHash = hash('sha256', $tokenForHash, true);

        $isValid = $configured
            && $token !== ''
            && hash_equals($expectedHash, $actualHash);

        if (!$isValid) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $next($request);
    }
}
