<?php

namespace Vut2\Component\OpenIDConnectClient\Provider;

use GuzzleHttp\Exception\BadResponseException;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class VutProvider extends GenericProvider
{
	use BearerAuthorizationTrait;

	protected string $baseUrl = 'https://id.vut.cz';

	/**
	 * @var string If set, this will be sent to google as the "prompt" parameter.
	 * @link https://developers.google.com/identity/protocols/OpenIDConnect#authenticationuriparameters
	 */
	protected $prompt;

	/**
	 * @var array<string> List of scopes that will be used for authentication.
	 * @link https://developers.google.com/identity/protocols/googlescopes
	 */
	protected $scopes = [];

	protected ?string $urlEndSession = null;
	protected ?string $urlRevokeToken = null;

	/**
	 * @param array<string, mixed> $options
	 * @param array<string, mixed> $collaborators
	 */
	public function __construct(array $options = [], array $collaborators = [])
	{
		if (empty($options['urlAuthorize'])) {
			$options['urlAuthorize'] = $this->baseUrl . '/oauth2/authorize';
		}
		if (empty($options['urlAccessToken'])) {
			$options['urlAccessToken'] = $this->baseUrl . '/oauth2/token';
		}
		if (empty($options['urlResourceOwnerDetails'])) {
			$options['urlResourceOwnerDetails'] = $this->baseUrl . '/oidc/userinfo';
		}
		if (empty($options['urlEndSession'])) {
			$options['urlEndSession'] = $this->baseUrl . '/oauth2/endSession';
		}
		if (empty($options['urlRevokeToken'])) {
			$options['urlRevokeToken'] = $this->baseUrl . '/oauth2/revoke';
		}

		if (empty($options['pkceMethod'])) {
			$options['pkceMethod'] = self::PKCE_METHOD_S256;
		}

		parent::__construct($options, $collaborators);
	}

	/**
	 * Get revoke token url to revoke token
	 *
	 * @param array<string, string|int> $params
	 * @return string
	 */
	public function getBaseRevokeTokenUrl(array $params): ?string
	{
		return $this->urlRevokeToken;
	}

	/**
	 * Revokes an access or refresh token using a specified token.
	 *
	 * @param string $token
	 * @param string|null $tokenTypeHint
	 * @return \Psr\Http\Message\ResponseInterface
	 */
	public function revokeAccessToken(string $token, string $tokenTypeHint = null): ResponseInterface
	{
		$params = [
			'client_id' => $this->clientId,
			'client_secret' => $this->clientSecret,
			'token' => $token
		];
		if ($tokenTypeHint !== null) {
			$params += [
				'token_type_hint' => $tokenTypeHint
			];
		}

		$method = $this->getAccessTokenMethod();
		$url = $this->getBaseRevokeTokenUrl($params);
		$options = $this->optionProvider->getAccessTokenOptions($this->getAccessTokenMethod(), $params);
		$request = $this->getRequest($method, $url, $options);

		return $this->getRevokeResponse($request);
	}

	/**
	 * Obtain URL for logging out the user.
	 *
	 * @param array<string, string> $params
	 * @return string
	 */
	public function getLogoutUrl(array $params = [])
	{
		if (!$this->urlEndSession) {
			throw new \InvalidArgumentException('Missing end session url');
		}

		$urlParts = parse_url($this->urlEndSession);
		if (!is_array($urlParts)) {
			throw new \InvalidArgumentException('Incorrect end session url');
		}
		if (isset($urlParts['query'])) { // Avoid 'Undefined index: query'
			parse_str($urlParts['query'], $query);
		} else {
			$query = [];
		}

		$query['client_id'] = $this->clientId;

		if (!empty($params['post_logout_redirect_uri'])) {
			$query['post_logout_redirect_uri'] = $params['post_logout_redirect_uri'];
		}

		// Note that this will url_encode all values
		$urlParts['query'] = http_build_query($query);

		/** @phpstan-ignore-next-line */
		return $urlParts['scheme'] . '://' . $urlParts['host'] . (($urlParts['port'] ?? false) ? (':' . $urlParts['host']) : '') . $urlParts['path'] . '?' . $urlParts['query'];
	}

	/**
	 * Returns authorization parameters based on provided options.
	 *
	 * @param array<string, mixed> $options
	 * @return array<string, mixed> Authorization parameters
	 */
	protected function getAuthorizationParameters(array $options): array
	{
		if (empty($options['prompt']) && $this->prompt) {
			$options['prompt'] = $this->prompt;
		}

		// Default scopes MUST be included for OpenID Connect.
		// Additional scopes MAY be added by constructor or option.
		$scopes = array_merge($this->getDefaultScopes(), $this->scopes);

		if (!empty($options['scope'])) {
			$scopes = array_merge($scopes, $options['scope']);
		}

		$options['scope'] = array_unique($scopes);

		$options = parent::getAuthorizationParameters($options);

		// The "approval_prompt" MUST be removed as it is not supported by Google, use "prompt" instead:
		// https://developers.google.com/identity/protocols/oauth2/openid-connect#prompt
		unset($options['approval_prompt']);

		return $options;
	}

	protected function getScopeSeparator(): string
	{
		return ' ';
	}

	/**
	 * Create a resource owner object based on the given response and access token.
	 *
	 * @param array<string, mixed> $response The response from the OAuth server.
	 * @param AccessToken $token The access token.
	 * @return VutUser The created resource owner object.
	 */
	protected function createResourceOwner(array $response, AccessToken $token): VutUser
	{
		$user = new VutUser($response);

		return $user;
	}


	/**
	 * Sends a request and returns the parsed response.
	 *
	 * @param  RequestInterface $request
	 * @return ResponseInterface
	 * @throws IdentityProviderException
	 */
	public function getRevokeResponse(RequestInterface $request): ResponseInterface
	{
		try {
			$response = $this->getResponse($request);
		} catch (BadResponseException $e) {
			$response = $e->getResponse();
		}

		if ($response->getStatusCode() != 200) {
			throw new IdentityProviderException('Invalid status code', $response->getStatusCode(), $response->getBody());
		}

		return $response;
	}
}
