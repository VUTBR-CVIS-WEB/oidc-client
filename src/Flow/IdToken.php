<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Flow;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Parser;
use League\OAuth2\Client\Token\AccessToken;

final class IdToken extends AccessToken
{
	private ?Token\Plain $idToken;

	/**
	 * Constructor method for the class.
	 *
	 * @param array<string, mixed> $options An array of optional parameters (default: [])
	 * @return void
	 */
	public function __construct(array $options = [])
	{
		parent::__construct($options);

		$this->idToken = null;

		if (isset($this->values['id_token'])) {
			// Signature is validated outside, this just parses the token
			/** @var Token\Plain $token */
			$token = (new Parser(new JoseEncoder()))->parse($this->values['id_token']);
			$this->idToken = $token;

			unset($this->values['id_token']);
		}
	}

	public function getIdToken(): ?Token\Plain
	{
		return $this->idToken ?? null;
	}

	/**
	 * Serializes the object to JSON format.
	 *
	 * @return array<string, mixed> The serialized object as an associative array.
	 */
	public function jsonSerialize(): array
	{
		$parameters = parent::jsonSerialize();

		if (isset($this->idToken)) {
			$parameters['id_token'] = $this->idToken->toString();
		}

		return $parameters;
	}
}
