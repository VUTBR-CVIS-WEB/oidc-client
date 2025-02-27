<?php

namespace Vut2\Component\OpenIDConnectClient\Provider;

use InvalidArgumentException;
use phpseclib3\Crypt\Common\AsymmetricKey;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA\Formats\Keys\JWK;
use phpseclib3\Math\BigInteger;

class JWKConverter
{
	/**
	 * Converts multiple JSON Web Keys (JWKs) to PEM format.
	 *
	 * @param array<array<string, int|string>> $jwkSet The array of JWKs to convert.
	 *
	 * @return array<string> An array of PEM representations of the JWKs.
	 *
	 * @throws InvalidArgumentException If the input $jwkSet contains non-array elements.
	 * @throws InvalidArgumentException If any of the JWKs in the $jwkSet is missing any of the required keys or if the key type is not RSA or if 'd' key is present.
	 */
	public function multipleToPEM(array $jwkSet): array
	{
		$keys = [];

		foreach($jwkSet as $jwk) {
			if(!is_array($jwk)) {
				throw new InvalidArgumentException('`multipleToPEM` can only take in an array of JWKs.');
			}

			try {
				$keys[] = $this->toPEM($jwk);
			} catch (InvalidArgumentException $e) {
				trigger_error($e->getMessage(), E_USER_WARNING);
			}
		}

		return $keys;
	}

	/**
	 * Converts a JSON Web Key (JWK) to PEM format.
	 *
	 * @param array<string, string|int> $jwk The JWK to convert. It must contain the following keys: 'e', 'n', 'kty'.
	 *
	 * @return string The PEM representation of the JWK.
	 * @throws InvalidArgumentException If any of the required keys is missing or if the key type is not RSA or if 'd' key is present.
	 * @throws \RuntimeException
	 *
	 */
	public function toPEM(array $jwk): string
	{
		if (!array_key_exists('kty', $jwk)) {
			throw new InvalidArgumentException('Missing key type.');
		}

		if (array_key_exists('d', $jwk)) {
			throw new InvalidArgumentException('Public key is currently only supported.');
		}

		return PublicKeyLoader::load(json_encode($jwk, JSON_THROW_ON_ERROR));
	}
}
