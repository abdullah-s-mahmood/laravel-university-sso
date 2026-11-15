<?php

declare(strict_types=1);

namespace UniversitySso\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use UniversitySso\BootstrapContext;

final class RequirePermission
{
    public function handle(Request $request, Closure $next, string $required): Response
    {
        $context = $request->attributes->get('sso.context');
        if ($request->attributes->get('sso.validated') !== true || ! $context instanceof BootstrapContext) {
            return response()->json(['message' => 'Authentication required.'], 401);
        }
        if (! in_array($required, $context->permissions(), true)) {
            return response()->json(['message' => 'Access denied.'], 403);
        }

        return $next($request);
    }
}
