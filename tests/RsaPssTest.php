<?php

namespace Vut2\Component\OpenIDConnectClient\Test;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use PHPUnit\Framework\TestCase;
use Vut2\Component\OpenIDConnectClient\Signer\RsaPss\Sha512;

class RsaPssTest extends TestCase
{
	/**
	 * {
	 * "jti": "some jti",
	 * "iss": "https://server.example.com",
	 * "sub": "some subject",
	 * "aud": "some audience",
	 * "nonce": "some nonce",
	 * "exp": 1636070123,
	 * "iat": 1636069000,
	 * "name": "Jane Doe",
	 * "email": "janedoe@example.com"
	 * }
	 */
	// phpcs:ignore Generic.Files.LineLength.TooLong
	private const ID_TOKEN = 'eyJraWQiOiIqcnAtc2lnbiNlOTA3ODljYS05ODE0LTQ0ZTgtOGRiZS1lNzJjYmEyZGIyYjgiLCJhbGciOiJQUzUxMiJ9.eyJhY3IiOiJsb2EzIiwic3ViIjoiMzg0ODViNWYtMjE5NC00Y2UzLThhODktOGE3OTE1MzZhMTAzIiwiYXVkIjoiMjFkMGM1MjctM2FhNC00MWE5LWI1ZjctOTdlMmRiY2ZhMDhhIiwiYmFua19pZCI6IjMxNzU0NzJlLWFhNzQtNGFhNy05MzQxLTNkMzI0ZjBhNDhhMiIsImF1dGhfdGltZSI6MTc0MDQ2NzExMCwiYW1yIjpbIm1mYSIsIm90cCJdLCJpc3MiOiJodHRwczovL29pZGMuc2FuZGJveC5iYW5raWQuY3ovIiwiZXhwIjoxNzQwNDY3NzI4LCJpYXQiOjE3NDA0NjcxMjgsIm5vbmNlIjoiMDgwYmE3ZjUtMDJjNS00YWZkLWFhNWItNTdiMDg2MGZkNjczIiwianRpIjoiNzhhOWQzNGEtNjZlOS00Y2M0LWJjZGQtNDRmNjAyZmJkM2NjIn0.HzranHfzPhfVNCh2meJck5sc_xFuLTrEUszkonqq6kdWxCdFE-6oM8vL3FZoXIp4LR_8aF_mzff5jIhil0PnIKgJrmQbeGobVPTy7RyybLYE6y6RHZTCAwv8uuEEfmkX74Z0uutOHvxVfK1kQ8DVhvFTiWVpr4ZKTjZO9iYW37G_a6rU0vRg5Je2Vnp7wdY2xzstwPyk1-j6VvPM0sNYCUI63lQnkwOcyJKEkmccOzjOxpvv-igwqNCSgYSAbwMCeOGyGO5Jy8aCG9eE-U8D7PrYU6a1kzJyRRfy0wiR6TAR9YX5ZY01sNemQLBp6W9HJS8VnkkCS29dFEtpb2YlBe-93kAjVhTYBL7RYWGRKCfXrcNmSYDDS_POo6YgZDHqm8Q8gbenneox28gsFrmNpqXaaPsxK7KsJBA2KQNG613JY4SpIrjanJy5pF15DLw_ULM6rrOuq-Q69w0o9XU2rPB1jzcBPP3k-WlTR1nkynTJgpvxHVvuEXiRMqJCZBkBirPjK-KySFTf4gTxlVHr-O3vSA7OnrKY9mpO4UC6vV-DGRZGjAPApCYIilxjxjy8LqPyMdRsHvga3h8iVgsvP7Wh0E5V0o4B8TSl7HYYzWLqvADJoLKpMxN6Ei_onG-DINWXaij-rgxVqzoJRzvCUD_k76oDa2i7v6q5CcezeoI';

	public function testRsaPs512s()
	{
		$token = (new Parser(new JoseEncoder()))->parse(self::ID_TOKEN);

		$key = InMemory::plainText('-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA35snlbRjiRXA0neHV2Xd
QhBzcGMbeQW77B+xCqL4OxMe78+F3NCxzWwCM3V/Gb0TL1ujCRvVW6BBUnoNFmtS
yncJM8eH7EhELmvoMMLl1PQp+65nq06AxWNnBXzcl4FmhWMSqniuXlruBRxUxusw
wcMVYYpDb7DJhvDHNSkOZxTSgY45w/Lj/kNpdoynw2Iumk8JDLAcAqDByAVc3h5V
JOwS9E63S84FJjUZTNruaSjGuPc36SHw8OhRtRfpuWyAKMINzaxeEOwirIiCNazM
XuWtH9I2cVeJNJBJ78rkUQv84KJTp60mhEWRnWpw/eyp8D+NOABQVoOYfrKtt7HI
XKr78zyg/yffof+5QkgXzrkr8Vluu1ERY+qVR6i14AF6bn7zw3cfFImPZGFdJWYJ
Z6h7PSsYT++a5BlItXia4M4e8ntKDdlQkhyPxLJUFRGHwcjQGJ3Nc2bd0CJtIMsC
GFOCJptmoLIpZW1eID+t8OYLCtk1nGfmpA4i48LcoAg55FTQPYisX0vYvDvQcj68
SJzxYdPhUvh0pWqmleofBOpTsGajuNIMFob9J2Dx08xdJhd2+QxxBgaXe8alIFon
11cgeqvf5+S0cb880irG8JEByk3ErA0uAtpodONi2VZ1xn3QyeQF5C2hCsANDbh8
R7BD7EFITbNigpelUrKx4J0CAwEAAQ==
-----END PUBLIC KEY-----
');

		$validator = new Validator();
		$signer = new Sha512();

		$this->assertTrue($validator->validate($token, new SignedWith($signer, $key)));
	}
}
