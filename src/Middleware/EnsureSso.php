<?php

declare(strict_types=1);

namespace UniversitySso\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use UniversitySso\AuthorizationException;
use UniversitySso\Sso;
use UniversitySso\UpstreamException;

final class EnsureSso
{
    public function __construct(private Sso $sso) {}

    public function handle(Request $request, Closure $next): Response
    {
        try {
            $context = $this->sso->validatedContext($request->session());
        } catch (UpstreamException) {
            return response()->json(['message' => 'Identity service unavailable.'], 503);
        } catch (AuthorizationException) {
            return response()->json(['message' => 'Access denied.'], 403);
        } catch (\Throwable) {
            try {
                $this->sso->logout($request->session());
            } catch (UpstreamException) {
                return response()->json(['message' => 'Session registry unavailable.'], 503);
            }

            return response()->json(['message' => 'Authentication required.'], 401);
        }
        $request->attributes->set('sso.context', $context);
        $request->attributes->set('sso.validated', true);

        return $next($request);
    }
}
