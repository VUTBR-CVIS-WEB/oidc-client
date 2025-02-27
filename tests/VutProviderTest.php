<?php

namespace Vut2\Component\OpenIDConnectClient\Test;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Lcobucci\JWT\Signer;
use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Grant\GrantFactory;
use League\OAuth2\Client\OptionProvider\PostAuthOptionProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\RequestFactory;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Vut2\Component\OpenIDConnectClient\Provider\VutOpenIDConnectProvider;

class VutProviderTest extends TestCase
{
	/**
	 * {
	 * "jti": "some jti",
	 * "iss": "https://server.example.com",
	 * "sub": "some subject",
	 * "aud": "some audience",
	 * "nonce": "some nonce",
	 * "exp": 1636070123,
	 * "iat": 1636069000,
	 * "name": "Jane Doe",
	 * "email": "janedoe@example.com"
	 * }
	 */
	// phpcs:ignore Generic.Files.LineLength.TooLong
	private const ID_TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImRjNWNkNDIxNWQ2NjYxYWMyODFiNDg5YjJhNWFiYjMzMTAxMGY2OTBmZmI4Y2ExNjBmZThlMDk1MDZjODU5MTUifQ.eyJhdWQiOiI0Yzk0NGI1Ny1mOTUxLTQ3ZWEtODhlNi1iM2Q0NDdmZWIyOWIiLCJpYXQiOjE3MTc0MTYyNjQsIm5iZiI6MTcxNzQxNjI2NCwiZXhwIjoxNzE3NDE5ODYzLCJzdWIiOiIxOTYyMzMiLCJpc3MiOiJodHRwczovL2hvdGRvZ2hvdXNlMjQuY2lzLnZ1dC5jei9hdXRoLXNlcnZlciIsInNpZCI6IjhiMjAyNWI4ZGMzYmE3MzFjZTQxMjJlMWU0YmNjMWY3NTNiYjQzZDFhNjNiYmM1YWYyNTU0MzEyZDJkMGI5ODAtNTc4IiwibmFtZSI6IkluZy4gUGF2ZWwgV2l0YXNzZWsiLCJmYW1pbHlfbmFtZSI6IldpdGFzc2VrIiwiZ2l2ZW5fbmFtZSI6IlBhdmVsIiwibWlkZGxlX25hbWUiOm51bGwsInByb2ZpbGUiOiJodHRwczovL3d3dy52dXQuY3ovbGlkZS8xOTYyMzMiLCJ3ZWJzaXRlIjpudWxsLCJnZW5kZXIiOiJtYWxlIiwiYmlydGhkYXRlIjoiMTk5NS0xMC0wNSIsImxvY2FsZSI6ImNzLUNaIiwidXBkYXRlZF9hdCI6MTY5Nzc2NjM1MSwiYXV0aF90aW1lIjoxNzE3NDE2MjYyLCJub25jZSI6IlZ0ak50R0NEWWlYSDJ3eTM3UUI5bHFMRk9iUk8wM2JvWmxIN0lHbkVhMGx4M3hLbVU0UjBkSXJpT0JWWlNCNWwiLCJqdGkiOiIzNjdlYzVhZWI2ODMyZGUwMzI2OGRjNjU4ZjQ2N2E4Njg4NGUxMTYwNTliNDc4YzMwYjU0OWM2MTkyZmFkNDk1YmYzMWE4ZWQ2MDM0ZmU2MSJ9.KQMC79Y7GVwoR9SrSEi4GB3Ojc2JgW7BA2K22_1BEG9hzuxhxKrL70bBtC1gj1e-7aZwwqPyKIJ9sen5xYmgzAN7Q8dcxq2xegDxzZhO9WJptzqt9R4Ii74dxEdi-0X7kQzfvydCbB6WejUPsjAHyF9QzxP_jw2ZpLEO7GHAOxU4AWv6xXtT1PhI6z3NTDjcm0R3le4kWFOtc4GiSmW4UvABB-rAUAkVh9uxfYSxM4pPqSMY9iyCuYpXEhuuXGMOU94XtJyEifKiWCnPvdl17y9Dxx8AtYyBsE5YCLGEl5RykuFz1SS_el-lQmv326YLyhCqzwPKmp1gEBlxS_F0tQ';

	/** @var VutOpenIDConnectProvider */
	protected $provider;
	/**
	 * @var GrantFactory
	 */
	private $grantFactory;
	/**
	 * @var Signer|(Signer&object&MockObject)|(Signer&MockObject)|(object&MockObject)|MockObject
	 */
	private $signer;

	protected function setUp(): void
	{
		$this->grantFactory = $this->createMock(GrantFactory::class);
		$this->requestFactory = $this->createMock(RequestFactory::class);
		//$this->httpClient = $this->createMock(HttpClient::class);
		$this->optionProvider = $this->createMock(PostAuthOptionProvider::class);

		// Create a mock handler and add the mock response
		$mockHandler = new MockHandler([
			new Response(200, [], '{"issuer":"https://hotdoghouse24.cis.vut.cz/auth-server","authorization_endpoint":"https://test.id.vut.cz/auth/oauth2/authorize","token_endpoint":"https://test.id.vut.cz/auth/oauth2/token","userinfo_endpoint":"https://test.id.vut.cz/auth/oidc/userinfo","jwks_uri":"https://test.id.vut.cz/auth/.well-known/jwks.json","response_types_supported":["code"],"id_token_signing_alg_values_supported":["RS256"],"subject_types_supported":["pairwise"],"end_session_endpoint":"https://test.id.vut.cz/auth/oauth2/endSession","scopes_supported":["openid","profile","email"],"grant_types_supported":["authorization_code","refresh_token"],"frontchannel_logout_supported":true,"revocation_endpoint":"https://test.id.vut.cz/auth/common/oauth2/revoke"}'),
			new Response(200, [], '{"keys":[{"alg":"RS256","kty":"RSA","kid":"dc5cd4215d6661ac281b489b2a5abb331010f690ffb8ca160fe8e09506c85915","use":"sig","n":"rw-DV64b5jOb1Q9cji1X9F5p5O9Ol7BfyPZKnRvihW3XYPifLKpWLgBQzi0pyoSQnA1loYiZNuXUWWNARluUWQywv9SQPJbmZYi3eQ2dfOXwvOGWl7v-veI4QkRPE6m69rm-kQ_6CaQr6R_vkiaL4nFPiOs8gDnvipmn7osGgP01KArXLsr7P7Xp_yfKNkonEa37oNxI8VZuHeWGAVh_wQGD5vpFCrRC08_8YAkFMwwG-PN-HuJqdFInMzQ9zckvaFtP5Kn9gUuNKwHFAI1Pf5lis5RLSkdKEPbym33WIUuqVjCnDeWSmnNf33IMHgJB6KeuxOATM2lvTuSObV9IXw","e":"AQAB"}]}'),
		]);
		$handlerStack = HandlerStack::create($mockHandler);

		$this->signer = new Signer\Rsa\Sha256(); //$this->createMock(Signer::class);
		$this->provider = new \Vut2\Component\OpenIDConnectClient\Provider\VutOpenIDConnectProvider(
			[
				'clientId' => '4c944b57-f951-47ea-88e6-b3d447feb29b',
				'clientSecret' => 'some clientSecret',
				// Your server
				'redirectUri' => 'some redirectUri',
				'scopes' => [
					'openid',
					'email',
					'profile',
				],
				'issuer' => 'https://hotdoghouse24.cis.vut.cz/auth-server',
			],
			[
				'grantFactory' => $this->grantFactory,
				'signer' => $this->signer,
				'httpClient' => new Client(['handler' => $handlerStack]),
			],
		);

		$this->signer = $this->createMock(Signer::class);
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

	/**
	 * @throws IdentityProviderException
	 */
	public function testGetAccessToken(): void
	{
		$grant = $this->createMock(AbstractGrant::class);
		$options = ['required-parameter' => 'some-value', 'nbfToleranceSeconds' => 60 * 60 * 60 * 1000];

		// AbstractProvider::verifyGrant
		$this->mockParentClassForAccessToken($grant, $options);

		$this->provider->setNonce('VtjNtGCDYiXH2wy37QB9lqLFObRO03boZlH7IGnEa0lx3xKmU4R0dIriOBVZSB5l');
		// OpenIDConnectProvider::getAccessToken
		$this->provider->getAccessToken($grant, $options);
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

	/**
	 * @throws \JsonException
	 */
	private function mockParentClassForAccessToken(MockObject $grant, array $options): void
	{
		$this->grantFactory
			->expects(self::once())
			->method('checkGrant')
			->with(self::identicalTo($grant));

		$params = [
			'client_id' => '4c944b57-f951-47ea-88e6-b3d447feb29b',
			'client_secret' => 'some clientSecret',
			'redirect_uri' => 'some redirectUri',
		];

		$newParams = [
			'client_id' => '4c944b57-f951-47ea-88e6-b3d447feb29b',
			'client_secret' => 'some clientSecret',
			'redirect_uri' => 'some redirectUri',
			'grant_type' => 'authorization_code',
		];

		// AbstractProvider::getAccessToken
		$grant
			->expects(self::once())
			->method('prepareRequestParameters')
			// ->with(self::equalTo($params), self::equalTo($options))
			->willReturn($newParams);

		$responseBody = json_encode(
			['access_token' => 'some access-token', 'id_token' => self::ID_TOKEN],
			JSON_THROW_ON_ERROR,
		);

		$mockHandler = new MockHandler([
			new Response(200, [], $responseBody)
		]);
		$handlerStack = HandlerStack::create($mockHandler);

		$this->provider->setHttpClient(new Client(['handler' => $handlerStack]));

		// AbstractProvider::getParsedResponse
	}
}
