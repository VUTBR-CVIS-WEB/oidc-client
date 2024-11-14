<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Constraint\CannotValidateARegisteredClaim;
use Lcobucci\JWT\Validation\ConstraintViolation;

use function in_array;

final class DoesNotHaveClaim implements Constraint
{
	private string $claim;

	/** @param non-empty-string $claim */
	public function __construct(string $claim)
	{
		$this->claim = $claim;
		if (in_array($claim, Token\RegisteredClaims::ALL, true)) {
			throw CannotValidateARegisteredClaim::create($claim);
		}
	}

	/**
	 * @inheritDoc
	 */
	public function assert(Token $token): void
	{
		if (!$token instanceof UnencryptedToken) {
			throw ConstraintViolation::error('You should pass a plain token', $this);
		}

		$claims = $token->claims();

		if ($claims->has($this->claim)) {
			throw ConstraintViolation::error('The token must not have the claim "' . $this->claim . '"', $this);
		}
	}
}
