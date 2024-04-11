<?php

namespace Vut2\Component\OpenIDConnectClient\Provider;

use League\OAuth2\Client\Provider\GenericResourceOwner;

class VutUser extends GenericResourceOwner
{
	/**
	 * @param array<string, mixed> $response
	 */
	public function __construct(array $response)
	{
		parent::__construct($response, 'sub');
	}

	/**
	 * Get preferred display name.
	 *
	 * @return string
	 */
	public function getName(): ?string
	{
		return $this->response['name'] ?? null;
	}

	/**
	 * Get preferred first name.
	 *
	 * @return string|null
	 */
	public function getFirstName(): ?string
	{
		return $this->response['given_name'] ?? null;
	}

	/**
	 * Get preferred last name.
	 *
	 * @return string|null
	 */
	public function getLastName(): ?string
	{
		return $this->response['family_name'] ?? null;
	}

	/**
	 * Get locale.
	 *
	 * @return string|null
	 */
	public function getLocale(): ?string
	{
		return $this->response['locale'] ?? null;
	}

	/**
	 * Get email address.
	 *
	 * @return string|null
	 */
	public function getEmail(): ?string
	{
		return $this->response['email'] ?? null;
	}
}
