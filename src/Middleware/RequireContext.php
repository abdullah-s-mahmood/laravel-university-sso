<?php

declare(strict_types=1);

namespace UniversitySso\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use UniversitySso\BootstrapContext;

final class RequireContext
{
    public function handle(Request $request, Closure $next, ?string $required = null): Response
    {
        $context = $request->attributes->get('sso.context');
        if ($request->attributes->get('sso.validated') !== true || ! $context instanceof BootstrapContext) {
            return response()->json(['message' => 'Authentication required.'], 401);
        }
        $active = $context->activeContext();
        $id = $active['context_id'] ?? null;
        if (! is_string($id) || $id === '' || ($required !== null && ! hash_equals($required, $id))) {
            return response()->json(['message' => 'Context access denied.'], 403);
        }

        return $next($request);
    }
}
