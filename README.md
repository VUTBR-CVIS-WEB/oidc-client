# OAuth 2.0 OpenID Connect Client

This package uses the PHP League's [OAuth2 Client](https://github.com/thephpleague/oauth2-client) and this [JWT Token Library](https://github.com/lcobucci/jwt) to provide an OAuth2 OpenID Connect client.

## Requirements

The following versions of PHP are supported.

* PHP 7.4
* PHP 8.0
* PHP 8.1
* PHP 8.2
* PHP 8.3

## Usage
```php
<?php
$signer = new \Lcobucci\JWT\Signer\Rsa\Sha256();
$provider = new \Vut2\Component\OpenIDConnectClient\Provider\VutOpenIDConnectProvider(
	[
		'clientId' => 'some client id',
		'clientSecret' => 'client secret',
		// Your server
		'redirectUri' => 'http://localhost:8002/client.php',
		'scopes' => [
			'openid',
			'profile',
		],

		// Settings of the OP (OpenID Provider)
		// The issuer of the identity token (id_token) this will be compared with what is returned in the token.
		//'idTokenIssuer' => 'brentertainment.com',

		// Alternatively, you can use automatic discovery as long as your server
		// has the <issuer>/.well-known/openid-configuration endpoint.
		// This endpoint will then provide all provider settings above, so you only need to provide
		// your own clientId, clientSecret, and redirectUri.
		'issuer' => 'https://id.vut.cz/auth',
	],
	[
		'signer' => $signer,
	],
);

// send the authorization request
if (empty($_GET['code'])) {
    $redirectUrl = $provider->getAuthorizationUrl();
    header(sprintf('Location: %s', $redirectUrl), true, 302);
    return;
}

// receive authorization response
try {
    $token = $provider->getAccessToken('authorization_code', [
        'code' => $_GET['code']
    ]);
} catch (\OpenIDConnectClient\Exception\InvalidTokenException $e) {
    $errors = $provider->getValidatorChain()->getMessages();
    return;
}

$accessToken    = $token->getToken();
$refreshToken   = $token->getRefreshToken();
$expires        = $token->getExpires();
$hasExpired     = $token->hasExpired();
$idToken        = $token->getIdToken();
$email          = $idToken->claims()->get('email', false);
$allClaims      = $idToken->claims();

```

### Run the Example
An example client has been provided and can be found in the /examples directory of this repository.  To run the example you can utilize PHPs built-in web server.
```bash
$ php -S localhost:8002 client.php
```
Then open this link: [http://localhost:8002/](http://localhost:8002/)

### Token Verification
The id_token is verified using the lcobucci/jwt library.  You will need to pass the appropriate signer and publicKey to the OpenIdConnectProvider.


## Install

Via Composer

``` bash
$ composer require vutbr-cvis-web/oidc-client
```

## Clock difference tolerance in nbf

Some clock difference can be tolerated between the IdP and the SP by using the `nbfToleranceSeconds` option in the
`getAccessToken` method call.

```php
<?php

...
// receive authorization response
try {
    $token = $provider->getAccessToken('authorization_code', [
        'code' => $_GET['code'],
        //adds 60 seconds to currentTime to tolerate 1 minute difference in clocks between IdP and SP
        'nbfToleranceSeconds' => 60
    ]);
} catch (\OpenIDConnectClient\Exception\InvalidTokenException $e) {
    $errors = $provider->getValidatorChain()->getMessages();
    return;
}

```

## Refresh token and token revocation

Client also supports Refresh token grant and token revocation.

```php
<?php

...
try {
    $newAccessToken = $provider->getAccessToken('refresh_token', [
        'refresh_token' => $token->getRefreshToken()
    ]);

    echo "Refreshed access token: " . $newAccessToken->getToken() . "<br>";
    echo "Refreshed refresh token: " . $newAccessToken->getRefreshToken() . "<br>";
} catch (\Exception $e) {
    var_dump($e);
}

try {
  $response = $provider->revokeAccessToken($newAccessToken->getToken());
  echo "<pre>" . var_dump($response) . "</pre>";
} catch (\Exception $exception) {
    var_dump($exception);
}

try {
  $response = $provider->revokeAccessToken($newAccessToken->getRefreshToken());
  echo "<pre>" . var_dump($response) . "</pre>";
} catch (\Exception $exception) {
    echo "<pre>" . var_dump($exception) . "</pre>";
}
}

```
