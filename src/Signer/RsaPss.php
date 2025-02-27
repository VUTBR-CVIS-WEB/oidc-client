<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Signer;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\PrivateKey;
use phpseclib3\Crypt\RSA\PublicKey;
use phpseclib3\Exception\NoKeyLoadedException;

use function assert;
use function is_string;

abstract class RsaPss implements Signer
{
	private const MINIMUM_KEY_LENGTH = 2048;

	final public function sign(string $payload, Key $key): string
	{
		try {
			$private = PublicKeyLoader::loadPrivateKey($key->contents(), $key->passphrase());
		} catch (NoKeyLoadedException $e) {
			throw new InvalidKeyProvided('It was not possible to parse your key, reason: ' . $e->getMessage(), 0, $e);
		}

		if (! $private instanceof PrivateKey) {
			throw InvalidKeyProvided::incompatibleKeyType('RSA', get_class($private));
		}

		if ($private->getLength() < self::MINIMUM_KEY_LENGTH) {
			throw InvalidKeyProvided::tooShort(self::MINIMUM_KEY_LENGTH, $private->getLength());
		}

		$signature = $private
			->withPadding(RSA::SIGNATURE_PSS)
			->withHash($this->algorithm())
			->withMGFHash($this->algorithm())
			->sign($payload);

		/** @infection-ignore-all */
		assert(is_string($signature) && $signature !== '');

		return $signature;
	}

	final public function verify(string $expected, string $payload, Key $key): bool
	{
		try {
			$public = PublicKeyLoader::loadPublicKey($key->contents());
		} catch (NoKeyLoadedException $e) {
			throw new InvalidKeyProvided('It was not possible to parse your key, reason: ' . $e->getMessage(), 0, $e);
		}

		if (! $public instanceof PublicKey) {
			throw InvalidKeyProvided::incompatibleKeyType('RSA', get_class($public));
		}

		return $public
			->withPadding(RSA::SIGNATURE_PSS)
			->withHash($this->algorithm())
			->withMGFHash($this->algorithm())
			->verify($payload, $expected);
	}

	/**
	 * Returns which algorithm to be used to create/verify the signature (using phpseclib hash identifiers)
	 *
	 * @internal
	 */
	abstract public function algorithm(): string;
}
