<?php

namespace Vut2\Component\OpenIDConnectClient\Test;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use PHPUnit\Framework\TestCase;
use Vut2\Component\OpenIDConnectClient\Provider\VutOpenIDConnectProvider;

class VutProviderTest extends TestCase
{
	/** @var VutOpenIDConnectProvider */
	protected $provider;

	protected function setUp(): void
	{
		// Create a mock handler and add the mock response
		$mockHandler = new MockHandler([
			new Response(200, [], '{"issuer":"https://test.id.vut.cz/auth","authorization_endpoint":"https://test.id.vut.cz/auth/oauth2/authorize","token_endpoint":"https://test.id.vut.cz/auth/oauth2/token","userinfo_endpoint":"https://test.id.vut.cz/auth/oidc/userinfo","jwks_uri":"https://test.id.vut.cz/auth/.well-known/jwks.json","response_types_supported":["code"],"id_token_signing_alg_values_supported":["RS256"],"subject_types_supported":["pairwise"],"end_session_endpoint":"https://test.id.vut.cz/auth/oauth2/endSession","scopes_supported":["openid","profile","email"],"grant_types_supported":["authorization_code","refresh_token"],"frontchannel_logout_supported":true,"revocation_endpoint":"https://test.id.vut.cz/auth/common/oauth2/revoke"}'),
			new Response(200, [], '{"keys":[{"alg":"RS256","kty":"RSA","kid":"20cce57672f33e503f297dcbd91a38953bf7463c48a9b55eaa7d4b2d478459d2","use":"sig","n":"urSjGq2WvJxRvwY9cYDzo0M3lp7WDE_TyHzahK3bFhbfSG-jI8zCbn1SEMpUVr561-24TZSM8NuqspMFlZ0NTE9RrknFXdNrlI9MtqL_Bmp2cgzBCOLknM5c3KfwlTnGCP346RJr7csQJ_6vPcMstaCL4ZEBpMdw-Y-C-47RJodj9tonWe7S_HgIS4-mPXE1RzwyTqO6LxHEfZdcNEn2yL_donAF1mWldDl7tmskCYixfO9L6ACAmgzWL69S3dLiwtMbSolVscON-TwncFtOhRJ1hyKrR5sO_qW4Ln95CgjbgSYEsbcBFstnDIdjqOyFkLkqFYuOYDEG-_j2MeXgQPLPVC8_b4DR4L-WGjDto8f8dQkf2FjTziGCyu-zXxJJhdT9ZekpJjl6IvZKPnXTeKOTlSk9m6fxzsn1ijBa8GS280jOWMqw_eRJZd9dIRWUEgkx19asN39uw-pX-WkdBNAL5rBFSqG8Ztyg6dBiiK6msN7G6mf1OeIz2rBEFA4sMhcEysBSOzi3wdIXuQ8hCDtd6kVejdI2O2m8TFpLuWUywxA7eF6QgHo6IGmrCnvlQiMfS838wsK27Hhk2IjVP1FC7d2i1c_7vWQawpk3QpANk1qQV2hlKfKH5FDLbNczQOE53qdzadcKSU-bEXHjSy-B0rblT5mX-_kWaNRswv0","e":"AQAB"}]}'),
		]);
		$handlerStack = HandlerStack::create($mockHandler);

		$signer = new \Lcobucci\JWT\Signer\Rsa\Sha256();
		$this->provider = new \Vut2\Component\OpenIDConnectClient\Provider\VutOpenIDConnectProvider(
			[
				'clientId' => '4c944b57-f951-47ea-88e6-b3d447feb29b',
				'clientSecret' => 'abc123',
				// Your server
				'redirectUri' => 'http://localhost:8002/client.php',
				'scopes' => [
					'openid',
					'email',
					'profile',
				],
				'issuer' => 'https://test.id.vut.cz/auth',
			],
			[
				'signer' => $signer,
				'httpClient' => new Client(['handler' => $handlerStack]),
			],
		);
	}

	public function testAuthorizationUrl(): void
	{
		$url = $this->provider->getAuthorizationUrl();
		$uri = parse_url($url);
		parse_str($uri['query'], $query);

		self::assertArrayHasKey('client_id', $query);
		self::assertArrayHasKey('redirect_uri', $query);
		self::assertArrayHasKey('state', $query);
		self::assertArrayHasKey('scope', $query);
		//self::assertArrayHasKey('response_type', $query);
		//self::assertArrayHasKey('prompt', $query);

		self::assertStringContainsString('email', $query['scope']);
		self::assertStringContainsString('profile', $query['scope']);
		self::assertStringContainsString('openid', $query['scope']);

		self::assertNotEmpty($this->provider->getState());
	}

	public function testBaseAccessTokenUrl(): void
	{
		$url = $this->provider->getBaseAccessTokenUrl([]);
		$uri = parse_url($url);

		self::assertEquals('/auth/oauth2/token', $uri['path']);
	}

	/**
	 * @link https://accounts.google.com/.well-known/openid-configuration
	 */
	public function testResourceOwnerDetailsUrl(): void
	{
		$token = $this->mockAccessToken();

		$url = $this->provider->getResourceOwnerDetailsUrl($token);

		self::assertEquals('https://test.id.vut.cz/auth/oidc/userinfo', $url);
	}

	public function testUserData(): void
	{
		$response = [
			'sub' => '12345',
			'email' => 'mock.name@example.com',
			'name' => 'mock name',
			'given_name' => 'mock',
			'family_name' => 'name',
		];

		// Create a mock handler and add the mock response
		$mockHandler = new MockHandler([
			new Response(200, [], json_encode($response))
		]);
		$handlerStack = HandlerStack::create($mockHandler);

		$this->provider->setHttpClient(new Client(['handler' => $handlerStack]));

		// Execute
		$user = $this->provider->getResourceOwner($this->mockAccessToken());

		self::assertInstanceOf(ResourceOwnerInterface::class, $user);

		self::assertEquals(12345, $user->getId());
		self::assertEquals('mock name', $user->getName());
		self::assertEquals('mock', $user->getFirstName());
		self::assertEquals('name', $user->getLastName());
		self::assertEquals('mock.name@example.com', $user->getEmail());

		$user = $user->toArray();

		self::assertArrayHasKey('sub', $user);
		self::assertArrayHasKey('name', $user);
		self::assertArrayHasKey('email', $user);
		self::assertArrayHasKey('family_name', $user);
	}

	private function mockAccessToken(): AccessToken
	{
		return new AccessToken([
			'access_token' => 'mock_access_token',
		]);
	}
}
