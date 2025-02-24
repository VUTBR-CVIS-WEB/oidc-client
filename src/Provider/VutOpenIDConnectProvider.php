<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Provider;

use GuzzleHttp\Client as HttpClient;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Constraint\HasClaimWithValue;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Lcobucci\JWT\Validation\Validator;
use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Grant\RefreshToken;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use League\OAuth2\Client\Tool\RequestFactory;
use Psr\Cache\CacheItemPoolInterface;
use Vut2\Component\OpenIDConnectClient\Constraint\DoesNotHaveClaim;
use Vut2\Component\OpenIDConnectClient\Constraint\HasSubOrSid;
use Vut2\Component\OpenIDConnectClient\Constraint\NotEmpty;
use Vut2\Component\OpenIDConnectClient\Exception\InvalidConfigurationException;
use Vut2\Component\OpenIDConnectClient\Exception\InvalidTokenException;
use Vut2\Component\OpenIDConnectClient\Flow\IdToken;

class VutOpenIDConnectProvider extends VutProvider
{
	protected Signer $signer;

	/** @var string|array<string> */
	protected $publicKey;
	protected string $idTokenIssuer;
	protected ?CacheItemPoolInterface $cache = null;

	protected ?string $nonce = null;

	/**
	 * @param array<string, mixed> $options
	 * @param array<string, mixed> $collaborators
	 * @throws IdentityProviderException
	 */
	public function __construct(array $options = [], array $collaborators = [])
	{
		if (!$collaborators['signer'] instanceof Signer) {
			throw new \InvalidArgumentException(sprintf('Signer must be instance of %s', Signer::class));
		}
		$this->signer = $collaborators['signer'];
		if (isset($collaborators['cache'])) {
			if (!$collaborators['cache'] instanceof CacheItemPoolInterface) {
				throw new \InvalidArgumentException(sprintf('Cache must be instance of %s', CacheItemPoolInterface::class));
			}
			$this->cache = $collaborators['cache'];
		}

		if (empty($options['scopes'])) {
			$options['scopes'] = [];
		} elseif (!is_array($options['scopes'])) {
			$options['scopes'] = [$options['scopes']];
		}

		if (!in_array('openid', $options['scopes'], true)) {
			$options['scopes'][] = 'openid';
		}

		// Using discovery
		if (isset($options['issuer']) && is_string($options['issuer'])) {
			if (empty($collaborators['requestFactory'])) {
				$collaborators['requestFactory'] = new RequestFactory();
			}
			$this->setRequestFactory($collaborators['requestFactory']);

			if (empty($collaborators['httpClient'])) {
				$client_options = $this->getAllowedClientOptions($options);

				$collaborators['httpClient'] = new HttpClient(
					array_intersect_key($options, array_flip($client_options))
				);
			}
			$this->setHttpClient($collaborators['httpClient']);

			$options = $this->discoverConfiguration($options['issuer'], $options);
		}

		parent::__construct($options, $collaborators);
	}

	/**
	 * Retrieves the nonce.
	 *
	 * @return ?string The nonce value, or null if it is not set.
	 */
	public function getNonce(): ?string
	{
		return $this->nonce;
	}

	/**
	 * Sets the nonce value.
	 *
	 * @param ?string $nonce The nonce value.
	 *
	 * @return void
	 */
	public function setNonce(?string $nonce): void
	{
		$this->nonce = $nonce;
	}

	/**
	 * Requests an access token using a specified grant and option set.
	 *
	 * @param string|AbstractGrant $grant
	 * @param array<string, mixed> $options
	 * @return AccessTokenInterface
	 * @throws IdentityProviderException
	 */
	public function getAccessToken($grant, array $options = [])
	{
		$accessToken = parent::getAccessToken($grant, $options);
		if ((string)$grant == 'refresh_token') {
			return $accessToken;
		}

		if (!$accessToken instanceof IdToken) {
			throw new InvalidTokenException('Received wrong access token type');
		}
		$token = $accessToken->getIdToken();

		// id_token is empty.
		if ($token === null) {
			$message = 'Expected an id_token but did not receive one from the authorization server.';
			throw new InvalidTokenException($message);
		}

		// If the ID Token is received via direct communication between the Client and the Token Endpoint
		// (which it is in this flow), the TLS server validation MAY be used to validate the issuer in place of checking
		// the token signature. The Client MUST validate the signature of all other ID Tokens according to JWS [JWS]
		// using the algorithm specified in the JWT alg Header Parameter. The Client MUST use the keys provided by
		// the Issuer.
		//
		// The alg value SHOULD be the default of RS256 or the algorithm sent by the Client in the
		// id_token_signed_response_alg parameter during Registration.
		$verified = false;
		foreach ($this->getPublicKeys() as $key) {
			if ($this->validateSignature($token, $key) !== false) {
				$verified = true;
				break;
			}
		}

		if (!$verified) {
			$message = 'Received an invalid id_token from authorization server.';
			throw new InvalidTokenException($message);
		}

		// validations
		// @see http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
		$nbfToleranceSeconds = (isset($options['nbfToleranceSeconds']) && is_int($options['nbfToleranceSeconds'])) ? (int)$options['nbfToleranceSeconds'] : 0;

		$constraints = [
			new IssuedBy($this->getIdTokenIssuer()),
			new PermittedFor($this->clientId),
			new StrictValidAt(SystemClock::fromUTC(), new \DateInterval("PT{$nbfToleranceSeconds}S")),
			// new HasClaimWithValue('auth_time', $currentTime),
			new NotEmpty('sub'),
			new HasClaimWithValue('nonce', $this->nonce),
		];

		// If the ID Token contains multiple audiences, the Client SHOULD verify that an azp Claim is present.
		// If an azp (authorized party) Claim is present, the Client SHOULD verify that its client_id is the Claim Value.
		if ($token->claims()->has('azp')) {
			$constraints[] = new HasClaimWithValue('azp', $this->clientId);
		}

		try {
			foreach ($constraints as $constraint) {
				$constraint->assert($token);
			}
		} catch (ConstraintViolation $e) {
			throw new InvalidTokenException('The id_token did not pass validation. ' . $e->getMessage());
		}

		return $accessToken;
	}

	/**
	 * Parse and validate logout token.
	 *
	 * @param string $logoutToken
	 * @param array<string, mixed> $options
	 * @return Token
	 * @throws IdentityProviderException
	 */
	public function getLogoutToken(string $logoutToken, array $options = []): Token
	{
		$token = (new Parser(new JoseEncoder()))->parse($logoutToken);

		$verified = false;
		foreach ($this->getPublicKeys() as $key) {
			if ($this->validateSignature($token, $key) !== false) {
				$verified = true;
				break;
			}
		}

		if (!$verified) {
			$message = 'Received an invalid logout_token from authorization server.';
			throw new InvalidTokenException($message);
		}

		// validations
		// @see http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
		$nbfToleranceSeconds = (isset($options['nbfToleranceSeconds']) && is_int($options['nbfToleranceSeconds'])) ? (int)$options['nbfToleranceSeconds'] : 0;

		$expectedEvents = json_encode(["http://schemas.openid.net/event/backchannel-logout" => []]);
		if ($expectedEvents === false) {
			$message = 'Received an invalid logout_token from authorization server.';
			throw new InvalidTokenException($message);
		}

		$constraints = [
			new IssuedBy($this->getIdTokenIssuer()),
			new PermittedFor($this->clientId),
			new StrictValidAt(SystemClock::fromUTC(), new \DateInterval("PT{$nbfToleranceSeconds}S")),
			new HasSubOrSid(), // A Logout Token MUST contain either a sub or a sid Claim, and MAY contain both.
			new DoesNotHaveClaim('nonce'), // PROHIBITED. A nonce Claim MUST NOT be present.
			new HasClaimWithValue('events', $expectedEvents)
		];

		try {
			foreach ($constraints as $constraint) {
				$constraint->assert($token);
			}
		} catch (ConstraintViolation $e) {
			throw new InvalidTokenException('The logout_token did not pass validation. ' . $e->getMessage());
		}

		return $token;
	}

	/**
	 * Returns all options that are required.
	 *
	 * @return array<string>
	 */
	protected function getRequiredOptions(): array
	{
		$options = parent::getRequiredOptions();
		$options[] = 'publicKey';
		$options[] = 'idTokenIssuer';

		return $options;
	}

	/**
	 * Returns authorization parameters based on provided options.
	 *
	 * @param array<string, mixed> $options
	 * @return array<string, mixed> Authorization parameters
	 */
	protected function getAuthorizationParameters(array $options): array
	{
		$options = parent::getAuthorizationParameters($options);

		$this->nonce = $this->getRandomNonce();
		$options['nonce'] = $this->nonce;

		return $options;
	}

	/**
	 * Creates an access token from a response.
	 *
	 * The grant that was used to fetch the response can be used to provide
	 * additional context.
	 *
	 * @param array<string, mixed> $response
	 * @param AbstractGrant $grant
	 * @return AccessTokenInterface
	 */
	protected function createAccessToken(array $response, AbstractGrant $grant): AccessTokenInterface
	{
		if ($grant instanceof RefreshToken) {
			return parent::createAccessToken($response, $grant);
		}

		return new IdToken($response);
	}

	/**
	 * @inheritDoc
	 */
	public function getResourceOwner(AccessToken $token)
	{
		if ($token instanceof IdToken) {
			return $this->createResourceOwner($token->getIdToken()->claims()->all(), $token);
		}

		return parent::getResourceOwner($token);
	}


	/**
	 * Retrieves OpenID Connect configuration from a discovery endpoint
	 * (<$issuer>/.well-known/openid-configuration) and merges it into
	 * a given options array
	 *
	 * @param array<string, mixed> $options
	 * @return array<string, mixed>
	 * @throws InvalidConfigurationException
	 * @throws IdentityProviderException
	 */
	protected function discoverConfiguration(string $issuer, array $options): array
	{
		$uri = $issuer . '/.well-known/openid-configuration';

		$cacheId = hash('sha256', self::class . '_' . $uri);
		$cachedResponse = $this->cache ? $this->cache->getItem($cacheId) : null;
		$response = $cachedResponse ? $cachedResponse->get() : null;

		if (!$cachedResponse || !$cachedResponse->isHit()) {
			$request = $this->getRequest(self::METHOD_GET, $uri);
			$response = $this->getParsedResponse($request);
			if (is_array($response) === false) {
				throw new InvalidConfigurationException(
					'Invalid response received from discovery. Expected JSON.'
				);
			}
		}

		// Map configuration to options
		$optionMapping = [
			'idTokenIssuer' => [
				'name' => 'issuer',
				'required' => true
			],
			'urlAuthorize' => [
				'name' => 'authorization_endpoint',
				'required' => true
			],
			'urlAccessToken' => [
				'name' => 'token_endpoint',
				'required' => true
			],
			'urlResourceOwnerDetails' => [
				'name' => 'userinfo_endpoint',
				'required' => false
			],
			'urlEndSession' => [
				'name' => 'end_session_endpoint',
				'required' => false
			],
			'urlRevokeToken' => [
				'name' => 'revocation_endpoint',
				'required' => false,
			]
		];

		foreach ($optionMapping as $optionKey => $responseKey) {
			if (!isset($response[$responseKey['name']])) {
				if ($responseKey['required']) {
					throw new InvalidConfigurationException(
						"Required parameter {$responseKey['name']} missing in discovery configuration at $uri"
					);
				} else {
					continue;
				}
			}

			$options[$optionKey] = $response[$responseKey['name']];
		}

		if ($this->cache && !$cachedResponse->isHit()) {
			$cachedResponse->set($response);
			$cachedResponse->expiresAfter(3600);
			$this->cache->save($cachedResponse);
		}

		// Validate scopes
		/* todo: fix openid-configuration to show all possible scopes
		if (isset($response['scopes_supported'])) {
			$scopesSupported = $response['scopes_supported'];
			foreach ($options['scopes'] as $scope) {
				if (!in_array($scope, $scopesSupported, true)) {
					throw new InvalidConfigurationException(
						"Scope $scope is not supported in discovery configuration at $uri"
					);
				}
			}
		}
		*/

		// Set public key
		if (!isset($response["jwks_uri"])) {
			throw new InvalidConfigurationException(
				"Required parameter jwks_uri missing in discovery configuration at $uri"
			);
		}
		$jwksUri = $response["jwks_uri"];


		$cacheId = hash('sha256', self::class . '_' . $jwksUri);
		$cachedResponse = $this->cache ? $this->cache->getItem($cacheId) : null;
		$options['publicKey'] = $cachedResponse ? $cachedResponse->get() : null;

		if (!$cachedResponse || !$cachedResponse->isHit()) {
			$jwksRequest = $this->getRequest(self::METHOD_GET, $jwksUri);
			$jwksResponse = $this->getParsedResponse($jwksRequest);
			if (is_array($jwksResponse) === false || is_array($jwksResponse['keys'] ?? null) === false) {
				throw new InvalidConfigurationException(
					'Invalid response received from discovery. Expected JSON.'
				);
			}

			// We will only need signature keys supported by our signer
			$jwks = array_filter($jwksResponse['keys'], function ($jwk) {
				if (!is_array($jwk)) {
					return false;
				}
				if (isset($jwk['use']) && $jwk['use'] !== 'sig') {
					return false;
				}
				if (isset($jwk['alg']) && $jwk['alg'] !== $this->signer->algorithmId()) {
					return false;
				}

				return true;
			});

			if (count($jwks) === 0) {
				throw new InvalidConfigurationException(
					"No valid signing keys found in discovery at $uri"
				);
			}

			$jwkConverter = new JWKConverter();
			$options['publicKey'] = $jwkConverter->multipleToPEM($jwks);

			if ($this->cache) {
				$cachedResponse->set($options['publicKey']);
				$cachedResponse->expiresAfter(3600);
				$this->cache->save($cachedResponse);
			}
		}

		return $options;
	}

	/**
	 * Returns a new random string to use as nonce.
	 *
	 * @param int $length Length of the random string to be generated.
	 * @return string
	 */
	protected function getRandomNonce(int $length = 64)
	{
		return substr(
			strtr(
				base64_encode(random_bytes(max(1, $length))),
				'+/',
				'-_'
			),
			0,
			$length
		);
	}

	protected function validateSignature(Token $token, Key $key): bool
	{
		$validator = new Validator();

		return $validator->validate($token, new SignedWith($this->signer, $key));
	}

	/**
	 * Get the issuer of the OpenID Connect id_token
	 */
	protected function getIdTokenIssuer(): string
	{
		return $this->idTokenIssuer;
	}


	/**
	 * @return Key[]
	 */
	private function getPublicKeys(): array
	{
		if (is_array($this->publicKey)) {
			$self = $this;
			return array_map(
				static function (string $key) use ($self): Key {
					return $self->constructKey($key);
				},
				$this->publicKey,
			);
		}

		return [$this->constructKey($this->publicKey)];
	}

	private function constructKey(string $content): Key
	{
		if (strpos($content, 'file://') === 0) {
			return InMemory::file($content);
		}

		assert(!empty($content));
		return InMemory::plainText($content);
	}
}
