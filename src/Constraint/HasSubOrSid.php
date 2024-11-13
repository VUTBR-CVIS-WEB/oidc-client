<?php

namespace Vut2\Component\OpenIDConnectClient\Constraint;

use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Lcobucci\JWT\Token;

class HasSubOrSid implements Constraint
{
	/**
	 * @inheritDoc
	 */
	public function assert(Token $token): void
	{
		$hasSub = $token->claims()->has('sub');
		$hasSid = $token->claims()->has('sid');

		if (!$hasSub && !$hasSid) {
			throw ConstraintViolation::error('The logout token must contain either a "sub" or "sid" claim.', $this);
		}
	}
}
