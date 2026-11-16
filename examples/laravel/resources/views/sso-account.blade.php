<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>SSO consumer</title></head>
<body>
<h1>{{ $identity->person()['full_name'] ?? $identity->universityId() }}</h1>
<p>Identifier: {{ $identity->universityId() }}</p>
@if(config('university-sso.refresh.enabled'))
<form method="post" action="{{ route('sso.refresh') }}">@csrf<button>Refresh session</button></form>
@endif
<form method="post" action="{{ route('sso.logout') }}">@csrf<button>Local logout</button></form>
<form method="post" action="{{ route('sso.global-logout') }}">@csrf<button>Provider logout</button></form>
</body>
</html>
