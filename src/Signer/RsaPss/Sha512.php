<?php
declare(strict_types=1);

namespace Vut2\Component\OpenIDConnectClient\Signer\RsaPss;

use Vut2\Component\OpenIDConnectClient\Signer\RsaPss;

final class Sha512 extends RsaPss
{
	public function algorithmId(): string
	{
		return 'PS512';
	}

	public function algorithm(): string
	{
		return 'sha512';
	}
}
