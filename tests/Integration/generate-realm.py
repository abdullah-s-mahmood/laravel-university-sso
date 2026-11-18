import json, os
from pathlib import Path
clients = []
for client, host, port, secret in [('sdk-one', 'one.localhost', 3000, os.environ['SDK_ONE_SECRET']), ('sdk-two', 'two.localhost', 3001, os.environ['SDK_TWO_SECRET'])]:
    clients.append({
        'clientId': client, 'enabled': True, 'protocol': 'openid-connect',
        'publicClient': False, 'secret': secret, 'clientAuthenticatorType': 'client-secret', 'standardFlowEnabled': True,
        'implicitFlowEnabled': False, 'directAccessGrantsEnabled': False,
        'redirectUris': [f'https://{host}:{port}/auth/callback'],
        'attributes': {'pkce.code.challenge.method': 'S256', 'post.logout.redirect.uris': f'https://{host}:{port}/', 'backchannel.logout.session.required': 'true', 'backchannel.logout.url': f'http://127.0.0.1:{port + 5000}/auth/backchannel'},
        'protocolMappers': [{
            'name': 'sdk-audience', 'protocol': 'openid-connect',
            'protocolMapper': 'oidc-audience-mapper',
            'config': {'included.custom.audience': 'sdk-broker', 'access.token.claim': 'true', 'id.token.claim': 'false'}
        }]
    })
clients.append({
    'clientId': 'sdk-native', 'enabled': True, 'protocol': 'openid-connect',
    'publicClient': True, 'standardFlowEnabled': True,
    'implicitFlowEnabled': False, 'directAccessGrantsEnabled': False,
    'redirectUris': ['https://native.localhost:3002/auth/callback'],
    'attributes': {'pkce.code.challenge.method': 'S256'}
})
realm = {
    'realm': 'sdk-test', 'enabled': True, 'sslRequired': 'all',
    'registrationAllowed': False, 'defaultSignatureAlgorithm': 'RS256',
    'revokeRefreshToken': True, 'refreshTokenMaxReuse': 0,
    'clients': clients,
    'users': [{
        'username': os.environ['OIDC_TEST_USERNAME'], 'enabled': True,
        'firstName': 'Synthetic', 'lastName': 'Tester', 'email': 'synthetic@example.invalid',
        'emailVerified': True, 'requiredActions': [],
        'credentials': [{'type': 'password', 'temporary': False, 'value': os.environ['OIDC_TEST_PASSWORD']}]
    }]
}
Path(os.environ['INTEGRATION_RUNTIME'], 'realm.json').write_text(json.dumps(realm))
