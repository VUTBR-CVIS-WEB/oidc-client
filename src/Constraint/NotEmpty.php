<?php

namespace Vut2\Component\OpenIDConnectClient\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;

class NotEmpty implements Constraint
{
	private string $claimName;

	/**
	 * @param string $claimName
	 */
	public function __construct(string $claimName)
	{
		$this->claimName = $claimName;
	}

	/**
	 * @inheritDoc
	 */
	public function assert(Token $token): void
	{
		/** @var Token\Plain $token */
		$claims = $token->claims();

		if (empty($claims->get($this->claimName))) {
			throw new ConstraintViolation(sprintf('Token claim %s is missing or empty', $this->claimName));
		}
	}
}
