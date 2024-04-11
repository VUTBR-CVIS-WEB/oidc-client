<?php

require '../vendor/autoload.php';

ini_set('display_errors', 1);
ini_set('error_reporting', E_ALL);
ini_set('session.use_strict_mode', 1);

$success = session_start();

$key = sprintf('file://%s/public.key', realpath(__DIR__));

$signer = new \Lcobucci\JWT\Signer\Rsa\Sha256();
$provider = new \Vut2\Component\OpenIDConnectClient\Provider\VutOpenIDConnectProvider(
	[
		'clientId' => 'a57574b2-b7b2-4962-ad77-b908874691cc',
		'clientSecret' => 'abc123',
		'clientId' => '4c944b57-f951-47ea-88e6-b3d447feb29b',
		'clientSecret' => 'abc123',
		// Your server
		'redirectUri' => 'http://localhost:8002/client.php',
		//'redirectUri' => 'https://www.localhost/common/test/default',
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
		'issuer' => 'https://hotdoghouse24.cis.vut.cz/auth-server',
	],
	[
		'signer' => $signer,
		'http_client' => new GuzzleHttp\Client(),
	],
);

if (isset($_GET['code']) && isset($_SESSION['OAuth2.state']) && isset($_GET['state'])) {
	if ($_GET['state'] == $_SESSION['OAuth2.state']) {
		$provider->setNonce($_SESSION['OAuth2.nonce']);
		$provider->setPkceCode($_SESSION['OAuth2.pkce']);

		//unset($_SESSION['OAuth2.state']);
		//unset($_SESSION['OAuth2.nonce']);
		//unset($_SESSION['OAuth2.pkce']);

		// receive authorization response
		try {
			$token = $provider->getAccessToken(
				'authorization_code',
				['code' => $_GET['code']],
			);
		} catch (\Vut2\Component\OpenIDConnectClient\Exception\InvalidTokenException|\Exception $e) {
			var_dump($e);
			return;
		}

		$response = [
			'Token: ' . $token->getToken(),
			'Refresh Token: ' . $token->getRefreshToken(),
			'Expires: ' . $token->getExpires(),
			'Has Expired: ' . $token->hasExpired(),
			'All Claims: ' . print_r($token->getIdToken()->claims(), true),
		];

		echo implode('<br />', $response) . "<br>";

		$redirectUrl = $provider->getLogoutUrl();
		echo 'Logout URL: ';
		echo '<a href="' . $redirectUrl . '">' . $redirectUrl . '</a><br/>';

		try {
			$newAccessToken = $provider->getAccessToken('refresh_token', [
				'refresh_token' => $token->getRefreshToken()
			]);

			echo "Refreshed access token: " . $newAccessToken->getToken() . "<br>";
			echo "Refreshed refresh token: " . $newAccessToken->getRefreshToken() . "<br>";
		} catch (\Exception $e) {
			var_dump($e);
		}

		if ($newAccessToken) {

			echo "<br>Revoke access token<br>";
			try {
				$response = $provider->revokeAccessToken($newAccessToken->getToken());
				echo "<pre>" . var_dump($response) . "</pre>";
			} catch (\Exception $exception) {
				echo "<pre>" . var_dump($exception) . "</pre>";
			}

			echo "<br>Revoke refresh token<br>";
			try {
				$response = $provider->revokeAccessToken($newAccessToken->getRefreshToken());
				echo "<pre>" . var_dump($response) . "</pre>";
			} catch (\Exception $exception) {
				echo "<pre>" . var_dump($exception) . "</pre>";
			}
		}

		return;
	} else {
		//unset($_SESSION['OAuth2.state']);
		//unset($_SESSION['OAuth2.nonce']);
		//unset($_SESSION['OAuth2.pkce']);

		echo 'Invalid state';

		return null;
	}
}

// send the authorization request
if (empty($_GET['code'])) {
	$redirectUrl = $provider->getAuthorizationUrl();

	$_SESSION['OAuth2.state'] = $provider->getState();
	$_SESSION['OAuth2.pkce'] = $provider->getPkceCode();
	$_SESSION['OAuth2.nonce'] = $provider->getNonce();
	// header(sprintf('Location: %s', $redirectUrl), true, 302);
	echo '<a href="' . $redirectUrl . '">' . $redirectUrl . '</a><br/>';

	var_dump($_SESSION);

	return;
}

var_dump($_GET);
var_dump($_SESSION);
echo 'Tady se to nemělo dostat!';
