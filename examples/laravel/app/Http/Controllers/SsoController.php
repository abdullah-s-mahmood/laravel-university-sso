<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use UniversitySso\Sso;

final class SsoController
{
    public function login(Request $request, Sso $sso)
    {
        return redirect()->away($sso->authorizationUrl($request->session()));
    }

    public function callback(Request $request, Sso $sso)
    {
        $sso->callback($request->session(), (string) $request->query('state'), (string) $request->query('code'));

        return redirect()->route('sso.account');
    }

    public function account(Request $request)
    {
        return view('sso-account', ['identity' => $request->attributes->get('sso.context')]);
    }

    public function refresh(Request $request, Sso $sso)
    {
        abort_unless(config('university-sso.refresh.enabled'), 404);
        $sso->refresh($request->session());

        return redirect()->route('sso.account');
    }

    public function logout(Request $request, Sso $sso)
    {
        $sso->logout($request->session());

        return redirect('/');
    }

    public function globalLogout(Request $request, Sso $sso)
    {
        return redirect()->away($sso->logoutUrl($request->session()));
    }
}
