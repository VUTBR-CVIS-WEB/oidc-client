<?php

namespace Vut2\Component\OpenIDConnectClient\Test;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Lcobucci\JWT\Signer;
use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Grant\GrantFactory;
use League\OAuth2\Client\OptionProvider\PostAuthOptionProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\RequestFactory;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Vut2\Component\OpenIDConnectClient\Exception\InvalidTokenException;
use Vut2\Component\OpenIDConnectClient\Provider\VutOpenIDConnectProvider;

class VutOpenIDConnectProviderTest extends TestCase
{
	// phpcs:ignore Generic.Files.LineLength.TooLong
	private const BAD_ID_TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImRjNWNkNDIxNWQ2NjYxYWMyODFiNDg5YjJhNWFiYjMzMTAxMGY2OTBmZmI4Y2ExNjBmZThlMDk1MDZjODU5MTUifQ.eyJhdWQiOiI0Yzk0NGI1Ny1mOTUxLTQ3ZWEtODhlNi1iM2Q0NDdmZWIyOWIiLCJpYXQiOjE3MTc0MTYyNjQsIm5iZiI6MTcxNzQxNjI2NCwiZXhwIjoxNzE3NDE5ODYzLCJzdWIiOiIxOTYyMzMiLCJpc3MiOiJodHRwczovL2hvdGRvZ2hvdXNlMjQuY2lzLnZ1dC5jei9hdXRoLXNlcnZlciIsInNpZCI6IjhiMjAyNWI4ZGMzYmE3MzFjZTQxMjJlMWU0YmNjMWY3NTNiYjQzZDFhNjNiYmM1YWYyNTU0MzEyZDJkMGI5ODAtNTc4IiwibmFtZSI6IkluZy4gUGF2ZWwgV2l0YXNzZWsiLCJmYW1pbHlfbmFtZSI6IldpdGFzc2VrIiwiZ2l2ZW5fbmFtZSI6IlBhdmVsIiwibWlkZGxlX25hbWUiOm51bGwsInByb2ZpbGUiOiJodHRwczovL3d3dy52dXQuY3ovbGlkZS8xOTYyMzMiLCJ3ZWJzaXRlIjpudWxsLCJnZW5kZXIiOiJtYWxlIiwiYmlydGhkYXRlIjoiMTk5NS0xMC0wNSIsImxvY2FsZSI6ImNzLUNaIiwidXBkYXRlZF9hdCI6MTY5Nzc2NjM1MSwiYXV0aF90aW1lIjoxNzE3NDE2MjYyLCJub25jZSI6IlZ0ak50R0NEWWlYSDJ3eTM3UUI5bHFMRk9iUk8wM2JvWmxIN0lHbkVhMGx4M3hLbVU0UjBkSXJpT0JWWlNCNWwiLCJqdGkiOiIzNjdlYzVhZWI2ODMyZGUwMzI2OGRjNjU4ZjQ2N2E4Njg4NGUxMTYwNTliNDc4YzMwYjU0OWM2MTkyZmFkNDk1YmYzMWE4ZWQ2MDM0ZmU2MSJ9.KQMC79Y7GVwoR9SrSEi4GB3Ojc2JgW7BA2K22_1BEG9hzuxhxKrL70bBtC1gj1e-7aZwwqPyKIJ9sen5xYmgzAN7Q8dcxq2xegDxzZhO9WJptzqt9R4Ii74dxEdi-0X7kQzfvydCbB6WejUPsjAHyF9QzxP_jw2ZpLEO7GHAOxU4AWv6xXtT1PhI6z3NTDjcm0R3le4kWFOtc4GiSmW4UvABB-rAUAkVh9uxfYSxM4pPqSMY9iyCuYpXEhuuXGMOU94XtJyEifKiWCnPvdl17y9Dxx8AtYyBsE5YCLGEl5RykuFz1SS_el-lQmv326YLyhCqzwPKmp1gEBlxS_F0tQ';
	// phpcs:ignore Generic.Files.LineLength.TooLong
	private const ID_TOKEN = 'eyJraWQiOiIqcnAtc2lnbiNlOTA3ODljYS05ODE0LTQ0ZTgtOGRiZS1lNzJjYmEyZGIyYjgiLCJhbGciOiJQUzUxMiJ9.eyJhY3IiOiJsb2EzIiwic3ViIjoiMzg0ODViNWYtMjE5NC00Y2UzLThhODktOGE3OTE1MzZhMTAzIiwiYXVkIjoiMjFkMGM1MjctM2FhNC00MWE5LWI1ZjctOTdlMmRiY2ZhMDhhIiwiYmFua19pZCI6IjMxNzU0NzJlLWFhNzQtNGFhNy05MzQxLTNkMzI0ZjBhNDhhMiIsImF1dGhfdGltZSI6MTc0MDQ2NzExMCwiYW1yIjpbIm1mYSIsIm90cCJdLCJpc3MiOiJodHRwczovL29pZGMuc2FuZGJveC5iYW5raWQuY3ovIiwiZXhwIjoxNzQwNDY3NzI4LCJpYXQiOjE3NDA0NjcxMjgsIm5vbmNlIjoiMDgwYmE3ZjUtMDJjNS00YWZkLWFhNWItNTdiMDg2MGZkNjczIiwianRpIjoiNzhhOWQzNGEtNjZlOS00Y2M0LWJjZGQtNDRmNjAyZmJkM2NjIn0.HzranHfzPhfVNCh2meJck5sc_xFuLTrEUszkonqq6kdWxCdFE-6oM8vL3FZoXIp4LR_8aF_mzff5jIhil0PnIKgJrmQbeGobVPTy7RyybLYE6y6RHZTCAwv8uuEEfmkX74Z0uutOHvxVfK1kQ8DVhvFTiWVpr4ZKTjZO9iYW37G_a6rU0vRg5Je2Vnp7wdY2xzstwPyk1-j6VvPM0sNYCUI63lQnkwOcyJKEkmccOzjOxpvv-igwqNCSgYSAbwMCeOGyGO5Jy8aCG9eE-U8D7PrYU6a1kzJyRRfy0wiR6TAR9YX5ZY01sNemQLBp6W9HJS8VnkkCS29dFEtpb2YlBe-93kAjVhTYBL7RYWGRKCfXrcNmSYDDS_POo6YgZDHqm8Q8gbenneox28gsFrmNpqXaaPsxK7KsJBA2KQNG613JY4SpIrjanJy5pF15DLw_ULM6rrOuq-Q69w0o9XU2rPB1jzcBPP3k-WlTR1nkynTJgpvxHVvuEXiRMqJCZBkBirPjK-KySFTf4gTxlVHr-O3vSA7OnrKY9mpO4UC6vV-DGRZGjAPApCYIilxjxjy8LqPyMdRsHvga3h8iVgsvP7Wh0E5V0o4B8TSl7HYYzWLqvADJoLKpMxN6Ei_onG-DINWXaij-rgxVqzoJRzvCUD_k76oDa2i7v6q5CcezeoI';

	/** @var VutOpenIDConnectProvider */
	protected $provider;
	/**
	 * @var GrantFactory
	 */
	private $grantFactory;

	protected function setUp(): void
	{
		$this->grantFactory = $this->createMock(GrantFactory::class);
		$this->requestFactory = $this->createMock(RequestFactory::class);
		//$this->httpClient = $this->createMock(HttpClient::class);
		$this->optionProvider = $this->createMock(PostAuthOptionProvider::class);

		// Create a mock handler and add the mock response
		$mockHandler = new MockHandler([
			new Response(200, [], '{"introspection_endpoint_auth_signing_alg_values_supported":["HS256","HS512","RS256","RS512","PS512","ES512"],"request_parameter_supported":false,"authorize_endpoint":"https://oidc.sandbox.bankid.cz/auth","claims_parameter_supported":false,"introspection_endpoint":"https://oidc.sandbox.bankid.cz/token-info","profile_endpoint":"https://oidc.sandbox.bankid.cz/profile","issuer":"https://oidc.sandbox.bankid.cz/","id_token_encryption_enc_values_supported":["A256GCM"],"userinfo_encryption_enc_values_supported":["A256GCM"],"authorization_endpoint":"https://oidc.sandbox.bankid.cz/auth","service_documentation":"https://developer.bankid.cz/docs","introspection_endpoint_auth_methods_supported":["client_secret_post","client_secret_jwt","private_key_jwt"],"claims_supported":["addresses.buildingapartment","addresses.city","addresses.cityarea","addresses.country","addresses.evidencenumber","addresses.ruian_reference","addresses.street","addresses.streetnumber","addresses.type","addresses.zipcode","age","birthcountry","birthdate","birthnumber","birthplace","claims_updated","date_of_death","email","email_verified","family_name","gender","given_name","idcards.country","idcards.description","idcards.issue_date","idcards.issuer","idcards.number","idcards.type","idcards.valid_to","limited_legal_capacity","locale","majority","maritalstatus","middle_name","name","nationalities","nickname","paymentAccounts","paymentAccountsDetails","pep","phone_number","phone_number_verified","preferred_username","primary_nationality","sub","title_prefix","title_suffix","txn","updated_at","verified_claims.verification","zoneinfo"],"op_policy_uri":"https://developer.bankid.cz/documents/privacy-policy","token_endpoint_auth_methods_supported":["client_secret_post","client_secret_jwt","private_key_jwt"],"response_modes_supported":["query"],"backchannel_logout_session_supported":false,"token_endpoint":"https://oidc.sandbox.bankid.cz/token","response_types_supported":["code","token"],"request_uri_parameter_supported":true,"grant_types_supported":["authorization_code","implicit","refresh_token"],"ui_locales_supported":["cs"],"userinfo_endpoint":"https://oidc.sandbox.bankid.cz/userinfo","verification_endpoint":"https://oidc.sandbox.bankid.cz/verification","op_tos_uri":"https://developer.bankid.cz/documents/terms-of-use","ros_endpoint":"https://oidc.sandbox.bankid.cz/ros","require_request_uri_registration":true,"code_challenge_methods_supported":["plain","S256"],"id_token_encryption_alg_values_supported":["RSA-OAEP","RSA-OAEP-256","ECDH-ES"],"frontchannel_logout_session_supported":false,"claims_locales_supported":["en","en-US"],"request_object_signing_alg_values_supported":["PS512","ES512"],"request_object_encryption_alg_values_supported":["RSA-OAEP","RSA-OAEP-256","ECDH-ES"],"scopes_supported":["openid","offline_access","profile.addresses","profile.birthdate","profile.birthnumber","profile.birthplaceNationality","profile.email","profile.gender","profile.idcards","profile.legalstatus","profile.locale","profile.maritalstatus","profile.name","profile.paymentAccounts","profile.phonenumber","profile.titles","profile.updatedat","profile.zoneinfo","profile.verification","notification.claims_updated","sign.qualified","sign.officially_certified"],"backchannel_logout_supported":true,"check_session_iframe":"https://oidc.sandbox.bankid.cz/session-iframe","acr_values_supported":["loa3"],"request_object_encryption_enc_values_supported":["A256GCM"],"display_values_supported":["page"],"profile_signing_alg_values_supported":["PS512"],"userinfo_signing_alg_values_supported":["PS512"],"profile_encryption_enc_values_supported":["A256GCM"],"userinfo_encryption_alg_values_supported":["RSA-OAEP","RSA-OAEP-256","ECDH-ES"],"end_session_endpoint":"https://oidc.sandbox.bankid.cz/logout","token_endpoint_auth_signing_alg_values_supported":["HS256","HS512","RS256","RS512","PS512","ES512"],"frontchannel_logout_supported":true,"profile_encryption_alg_values_supported":["RSA-OAEP","RSA-OAEP-256","ECDH-ES"],"jwks_uri":"https://oidc.sandbox.bankid.cz/.well-known/jwks","subject_types_supported":["public","pairwise"],"id_token_signing_alg_values_supported":["PS512"]}'),
			new Response(200, [], '{"keys":[{"kty":"RSA","x5t#S256":"fYowjlnVtUVM3EvJahDnIBjZITeS2SK-9zeE4j3iZ-w","e":"AQAB","use":"enc","kid":"rp-encrypt#b892f5d3-7adb-4ec8-afa6-e28478ea902e","x5c":["MIIElTCCBBugAwIBAgICECwwCgYIKoZIzj0EAwMwfjELMAkGA1UEBhMCQ1oxDjAMBgNVBAgMBVByYWhhMSAwHgYDVQQKDBdCYW5rb3ZuaSBpZGVudGl0YSwgYS5zLjEdMBsGA1UEAwwUQmFua0lEIFByb2R1Y3Rpb24gQ0ExHjAcBgkqhkiG9w0BCQEWD2FkbWluQGJhbmtpZC5jejAeFw0yMTAzMTgwNzUwMDJaFw0yNDAzMTcwNzUwMDJaMFsxCzAJBgNVBAYTAkNaMQ4wDAYDVQQIDAVQcmFoYTEgMB4GA1UECgwXQmFua292bmkgaWRlbnRpdGEsIGEucy4xGjAYBgNVBAMMEUJhbmtJRCBwcm9kdWN0aW9uMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxFLhcDDXnkdcO7CV1gjm4pXu60VFVuVKdYazZ+Bv1EXZ8I6NNQ/yrS0fysyLdaeNEwTrQ2rhb2BjuaR9aOvrPdhFlS2yKZ+k4+wkWeioc6t3jZvb9fJvKpCxozMU8XwC/OVO81G3Az5Gyv/nAGCzNmHRsXUiJBA9gh5OVduBJyAZN6w7s8F4A+QQlSdbMkVduHpUqGlGbvDDZ0zpssJQv2pA3i6y3mfAEPccr75Vgx/le9+6PC/e7BaZFUY/BdP6KmesitPZgD6EACP/QUh21jHn0feGDV+nGkZswPxZp3FCEz6YnkZg24/C6JHOjUee/gATjjjUC+uxpVPLuUGjR+Rf0WMmczMec3LJTfXwhx33ai6nQ02vp8UUGzjfSzF0UiztrWJQ9pRgc4o95h4npcLO+n7uh3NVR2/nHtBPEYGvxxZyX50Ux8HibaHEKZvoQARQ6/MTKgo0FpjGd0G97BxB5FKxw7WwiSLI9USQuDubnE3xqnQMsgJcAlg2HcQkCMu5P+6H2mer9l3wm127KFDHaZeUvV8feEBX6juz4kguQwwtZg/Op1/Hbjh/+pRvUCnbj+erjLzX4Y1rwYZlTlg3QRTaTbxV+Qhfv5gO7ZTlXSvyCIWhKnUYc8EGT1VpKDhoOdzVM23VT5m9plZKZQsyrMJMD1DP15sh2Tj1/8ECAwEAAaOB4DCB3TAJBgNVHRMEAjAAMBEGCWCGSAGG+EIBAQQEAwIGQDAzBglghkgBhvhCAQ0EJhYkQmFua0lEIFByb2R1Y3Rpb24gQ2xpZW50IENlcnRpZmljYXRlMB0GA1UdDgQWBBRzRJstwoejw003aJ6fquk9rsU1QDAfBgNVHSMEGDAWgBQqoi9yTXXY0beUgU8zj/QtExL35jALBgNVHQ8EBAMCBBAwOwYDVR0fBDQwMjAwoC6gLIYqaHR0cHM6Ly9jYS5iYW5raWQuY3ovY3JsL3Byb2QvcHJvZC5jcmwuY3JsMAoGCCqGSM49BAMDA2gAMGUCMQCDv5oUXSpGdQFgSD9QPzl6pqTRX2zMeFT4OPj3IKSJPrdEi7A4iPTjWs9r2dm9ngsCMEwCMeFbc3iIA6H+iZGDEgls4pOJQAn5qNq1td9VQijqw+XSeGMkwYmtV/SvRlOyyw=="],"n":"xFLhcDDXnkdcO7CV1gjm4pXu60VFVuVKdYazZ-Bv1EXZ8I6NNQ_yrS0fysyLdaeNEwTrQ2rhb2BjuaR9aOvrPdhFlS2yKZ-k4-wkWeioc6t3jZvb9fJvKpCxozMU8XwC_OVO81G3Az5Gyv_nAGCzNmHRsXUiJBA9gh5OVduBJyAZN6w7s8F4A-QQlSdbMkVduHpUqGlGbvDDZ0zpssJQv2pA3i6y3mfAEPccr75Vgx_le9-6PC_e7BaZFUY_BdP6KmesitPZgD6EACP_QUh21jHn0feGDV-nGkZswPxZp3FCEz6YnkZg24_C6JHOjUee_gATjjjUC-uxpVPLuUGjR-Rf0WMmczMec3LJTfXwhx33ai6nQ02vp8UUGzjfSzF0UiztrWJQ9pRgc4o95h4npcLO-n7uh3NVR2_nHtBPEYGvxxZyX50Ux8HibaHEKZvoQARQ6_MTKgo0FpjGd0G97BxB5FKxw7WwiSLI9USQuDubnE3xqnQMsgJcAlg2HcQkCMu5P-6H2mer9l3wm127KFDHaZeUvV8feEBX6juz4kguQwwtZg_Op1_Hbjh_-pRvUCnbj-erjLzX4Y1rwYZlTlg3QRTaTbxV-Qhfv5gO7ZTlXSvyCIWhKnUYc8EGT1VpKDhoOdzVM23VT5m9plZKZQsyrMJMD1DP15sh2Tj1_8E"},{"kty":"RSA","x5t#S256":"R1wBUEl7t-SMd-Pgb2nPMmGU2EXtR_qexP8Ncokqxto","e":"AQAB","use":"sig","kid":"*rp-sign#e91789ca-9814-44e8-8dbe-e72cba2db2b8","x5c":["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"],"n":"xl-vf10Kl6EMHrqTiDCBsrlG4Ts49z1ZwJVHyI32xtPkKFhyJHclnZFIVJSl4jh0oxiv-h8Lw7xS8nulSTif8y-v_SF1jF_odr84SDvjg6OmmvRdqrHQHPt_m_kPaKOvjpsZXs49c933ap2WzDjQ8sL5Gr-FQohf2-O5a2yAPapEm_26W_TK9E0itnYCrYLVnxXafY0KGAT7j1qx2hfMkXDpTQ-5cjcJGL84yTvrs3Z-NrlG06t-ccqGTMXEDZ1IBKoP7kItUqQC9F5m97jhWdGKTyoMNCGM4HCLpCWYxG3pKd-YvXy5gEVKj7T36Gn4oRzcw7tyWNyzEpqEcJp17F5zqixTJjxFd5f563aQs_dB7yf8VkULFpoXlbvELwc4jaGF5dJ_dcN4mBjO2sF1nXYX_Oery24fhrkNo1Pg-loFnNMPEcI54wcGKYsw229WPjaYg165D905bJQ1yQxz-3umBtyPoHD2acI2iIBdP8qwVdJ5ATZmAydY5rgS0CV777S5hZ4xw2cWQVR03puqoPBwbWpbzJzI2xBGUmTdJzzdLH2xf8I8XAW2WjVYlcus93DRNKk1BuGrnkY6MvphZUiUBf_rzBZLpv5j4vVodtbp5NBb0cDorBLCFLVJ0DS8MI-ueyFACpfpVE_GdvER-0u7GeEzr44avouhRmy3pVU"},{"kty":"RSA","x5t#S256":"A8qAH7A1O4JkwOjOy_9u2V9CQmdN_8q9P3GASD6nSmk","e":"AQAB","use":"sig","kid":"*rp-sign#e90789ca-9814-44e8-8dbe-e72cba2db2b8","x5c":["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"],"n":"35snlbRjiRXA0neHV2XdQhBzcGMbeQW77B-xCqL4OxMe78-F3NCxzWwCM3V_Gb0TL1ujCRvVW6BBUnoNFmtSyncJM8eH7EhELmvoMMLl1PQp-65nq06AxWNnBXzcl4FmhWMSqniuXlruBRxUxuswwcMVYYpDb7DJhvDHNSkOZxTSgY45w_Lj_kNpdoynw2Iumk8JDLAcAqDByAVc3h5VJOwS9E63S84FJjUZTNruaSjGuPc36SHw8OhRtRfpuWyAKMINzaxeEOwirIiCNazMXuWtH9I2cVeJNJBJ78rkUQv84KJTp60mhEWRnWpw_eyp8D-NOABQVoOYfrKtt7HIXKr78zyg_yffof-5QkgXzrkr8Vluu1ERY-qVR6i14AF6bn7zw3cfFImPZGFdJWYJZ6h7PSsYT--a5BlItXia4M4e8ntKDdlQkhyPxLJUFRGHwcjQGJ3Nc2bd0CJtIMsCGFOCJptmoLIpZW1eID-t8OYLCtk1nGfmpA4i48LcoAg55FTQPYisX0vYvDvQcj68SJzxYdPhUvh0pWqmleofBOpTsGajuNIMFob9J2Dx08xdJhd2-QxxBgaXe8alIFon11cgeqvf5-S0cb880irG8JEByk3ErA0uAtpodONi2VZ1xn3QyeQF5C2hCsANDbh8R7BD7EFITbNigpelUrKx4J0"},{"kty":"EC","x5t#S256":"jCzQzpeGp6sKV3vrKPd8hxSsniTvkDobPZfMgpdHVQQ","use":"sig","crv":"P-384","kid":"mtls","x5c":["MIICxzCCAkygAwIBAgIQetKS6kSHAWSo1bx4rH3kEzAKBggqhkjOPQQDAzB+MQswCQYDVQQGEwJDWjEOMAwGA1UECAwFUHJhaGExIDAeBgNVBAoMF0Jhbmtvdm5pIGlkZW50aXRhLCBhLnMuMR0wGwYDVQQDDBRCYW5rSUQgUHJvZHVjdGlvbiBDQTEeMBwGCSqGSIb3DQEJARYPYWRtaW5AYmFua2lkLmN6MB4XDTI0MDIwODExMDAyMloXDTI1MDUwMzExMDEyMlowIjEgMB4GA1UEAxMXQmFua292bmkgaWRlbnRpdGEsIGEucy4wdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQ3JjfbMeRG5zuU7tgwV/9CQDMc2MnPRB2KMXsNmvqWMkkVEuWx42E06Uv7dXtJloLr52IWOP/s9oyM3GgmMkSh3sWJ1n7HmW4iSlDnIKrU+KU8qy90XyPX0JcoThkXwu6jgeowgecwDgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUqMXsv3pNOM0g5gDSunn+GfQJzeYwHwYDVR0jBBgwFoAUKqIvck112NG3lIFPM4/0LRMS9+YwFAYDVR0RBA0wC4IJYmFua2lkLmN6MGAGDCsGAQQBgqRkxihAAQRQME4CAQEEHHBoaWxpcHAubmFsaXZheWtpbkBiYW5raWQuY3oEK0poblpvSjFFUHRuYkpzS0hQWnhUWDZKZ3VjbjhwTmp0VE9YU0dieEExU3cwCgYIKoZIzj0EAwMDaQAwZgIxAKziYiP27xw1JHZYF2f1/YUVAW4y4WxNBWYvdTvSU49TX8FmRSQsuvEt53mQH/dREQIxAKcojWBNF6jmHIFHgBLXh2BoOAyGZAQvZraT1VmwkQk++8o5zZdX6mKfOsxQajjbnA=="],"x":"NyY32zHkRuc7lO7YMFf_QkAzHNjJz0QdijF7DZr6ljJJFRLlseNhNOlL-3V7SZaC","y":"6-diFjj_7PaMjNxoJjJEod7FidZ-x5luIkpQ5yCq1PilPKsvdF8j19CXKE4ZF8Lu"},{"kty":"RSA","x5t#S256":"fYowjlnVtUVM3EvJahDnIBjZITeS2SK-9zeE4j3iZ-w","e":"AQAB","use":"enc","kid":"rp_encrypt_b892f5d3_7adb_4ec8_afa6_e28478ea902e","x5c":["MIIElTCCBBugAwIBAgICECwwCgYIKoZIzj0EAwMwfjELMAkGA1UEBhMCQ1oxDjAMBgNVBAgMBVByYWhhMSAwHgYDVQQKDBdCYW5rb3ZuaSBpZGVudGl0YSwgYS5zLjEdMBsGA1UEAwwUQmFua0lEIFByb2R1Y3Rpb24gQ0ExHjAcBgkqhkiG9w0BCQEWD2FkbWluQGJhbmtpZC5jejAeFw0yMTAzMTgwNzUwMDJaFw0yNDAzMTcwNzUwMDJaMFsxCzAJBgNVBAYTAkNaMQ4wDAYDVQQIDAVQcmFoYTEgMB4GA1UECgwXQmFua292bmkgaWRlbnRpdGEsIGEucy4xGjAYBgNVBAMMEUJhbmtJRCBwcm9kdWN0aW9uMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxFLhcDDXnkdcO7CV1gjm4pXu60VFVuVKdYazZ+Bv1EXZ8I6NNQ/yrS0fysyLdaeNEwTrQ2rhb2BjuaR9aOvrPdhFlS2yKZ+k4+wkWeioc6t3jZvb9fJvKpCxozMU8XwC/OVO81G3Az5Gyv/nAGCzNmHRsXUiJBA9gh5OVduBJyAZN6w7s8F4A+QQlSdbMkVduHpUqGlGbvDDZ0zpssJQv2pA3i6y3mfAEPccr75Vgx/le9+6PC/e7BaZFUY/BdP6KmesitPZgD6EACP/QUh21jHn0feGDV+nGkZswPxZp3FCEz6YnkZg24/C6JHOjUee/gATjjjUC+uxpVPLuUGjR+Rf0WMmczMec3LJTfXwhx33ai6nQ02vp8UUGzjfSzF0UiztrWJQ9pRgc4o95h4npcLO+n7uh3NVR2/nHtBPEYGvxxZyX50Ux8HibaHEKZvoQARQ6/MTKgo0FpjGd0G97BxB5FKxw7WwiSLI9USQuDubnE3xqnQMsgJcAlg2HcQkCMu5P+6H2mer9l3wm127KFDHaZeUvV8feEBX6juz4kguQwwtZg/Op1/Hbjh/+pRvUCnbj+erjLzX4Y1rwYZlTlg3QRTaTbxV+Qhfv5gO7ZTlXSvyCIWhKnUYc8EGT1VpKDhoOdzVM23VT5m9plZKZQsyrMJMD1DP15sh2Tj1/8ECAwEAAaOB4DCB3TAJBgNVHRMEAjAAMBEGCWCGSAGG+EIBAQQEAwIGQDAzBglghkgBhvhCAQ0EJhYkQmFua0lEIFByb2R1Y3Rpb24gQ2xpZW50IENlcnRpZmljYXRlMB0GA1UdDgQWBBRzRJstwoejw003aJ6fquk9rsU1QDAfBgNVHSMEGDAWgBQqoi9yTXXY0beUgU8zj/QtExL35jALBgNVHQ8EBAMCBBAwOwYDVR0fBDQwMjAwoC6gLIYqaHR0cHM6Ly9jYS5iYW5raWQuY3ovY3JsL3Byb2QvcHJvZC5jcmwuY3JsMAoGCCqGSM49BAMDA2gAMGUCMQCDv5oUXSpGdQFgSD9QPzl6pqTRX2zMeFT4OPj3IKSJPrdEi7A4iPTjWs9r2dm9ngsCMEwCMeFbc3iIA6H+iZGDEgls4pOJQAn5qNq1td9VQijqw+XSeGMkwYmtV/SvRlOyyw=="],"n":"xFLhcDDXnkdcO7CV1gjm4pXu60VFVuVKdYazZ-Bv1EXZ8I6NNQ_yrS0fysyLdaeNEwTrQ2rhb2BjuaR9aOvrPdhFlS2yKZ-k4-wkWeioc6t3jZvb9fJvKpCxozMU8XwC_OVO81G3Az5Gyv_nAGCzNmHRsXUiJBA9gh5OVduBJyAZN6w7s8F4A-QQlSdbMkVduHpUqGlGbvDDZ0zpssJQv2pA3i6y3mfAEPccr75Vgx_le9-6PC_e7BaZFUY_BdP6KmesitPZgD6EACP_QUh21jHn0feGDV-nGkZswPxZp3FCEz6YnkZg24_C6JHOjUee_gATjjjUC-uxpVPLuUGjR-Rf0WMmczMec3LJTfXwhx33ai6nQ02vp8UUGzjfSzF0UiztrWJQ9pRgc4o95h4npcLO-n7uh3NVR2_nHtBPEYGvxxZyX50Ux8HibaHEKZvoQARQ6_MTKgo0FpjGd0G97BxB5FKxw7WwiSLI9USQuDubnE3xqnQMsgJcAlg2HcQkCMu5P-6H2mer9l3wm127KFDHaZeUvV8feEBX6juz4kguQwwtZg_Op1_Hbjh_-pRvUCnbj-erjLzX4Y1rwYZlTlg3QRTaTbxV-Qhfv5gO7ZTlXSvyCIWhKnUYc8EGT1VpKDhoOdzVM23VT5m9plZKZQsyrMJMD1DP15sh2Tj1_8E"}]}'),
		]);
		$handlerStack = HandlerStack::create($mockHandler);

		$this->provider = new \Vut2\Component\OpenIDConnectClient\Provider\VutOpenIDConnectProvider(
			[
				'clientId' => '4c944b57-f951-47ea-88e6-b3d447feb29b',
				'clientSecret' => 'some clientSecret',
				// Your server
				'redirectUri' => 'some redirectUri',
				'scopes' => [
					'openid',
					'email',
					'profile',
				],
				'issuer' => 'https://oidc.sandbox.bankid.cz/',
			],
			[
				'grantFactory' => $this->grantFactory,
				'httpClient' => new Client(['handler' => $handlerStack]),
			],
		);
	}

	/**
	 * @throws IdentityProviderException
	 */
	public function testGetAccessToken(): void
	{
		$grant = $this->createMock(AbstractGrant::class);
		$options = ['required-parameter' => 'some-value', 'nbfToleranceSeconds' => 60 * 60 * 60 * 1000];

		$this->mockParentClassForAccessToken($grant, $options, self::ID_TOKEN);

		$this->provider->setNonce('VtjNtGCDYiXH2wy37QB9lqLFObRO03boZlH7IGnEa0lx3xKmU4R0dIriOBVZSB5l');
		// OpenIDConnectProvider::getAccessToken
		$this->provider->getAccessToken($grant, $options);
	}


	/**
	 * @throws IdentityProviderException
	 */
	public function testGetAccessTokenInvalid(): void
	{
		$this->expectException(InvalidTokenException::class);

		$grant = $this->createMock(AbstractGrant::class);
		$options = ['required-parameter' => 'some-value', 'nbfToleranceSeconds' => 60 * 60 * 60 * 1000];

		$this->mockParentClassForAccessToken($grant, $options, self::BAD_ID_TOKEN);

		$this->provider->setNonce('VtjNtGCDYiXH2wy37QB9lqLFObRO03boZlH7IGnEa0lx3xKmU4R0dIriOBVZSB5l');
		// OpenIDConnectProvider::getAccessToken
		$this->provider->getAccessToken($grant, $options);
	}

	/**
	 * @throws \JsonException
	 */
	private function mockParentClassForAccessToken(MockObject $grant, array $options, string $idToken): void
	{
		$newParams = [
			'client_id' => '4c944b57-f951-47ea-88e6-b3d447feb29b',
			'client_secret' => 'some clientSecret',
			'redirect_uri' => 'some redirectUri',
			'grant_type' => 'authorization_code',
		];

		// AbstractProvider::getAccessToken
		$grant
			->method('prepareRequestParameters')
			// ->with(self::equalTo($params), self::equalTo($options))
			->willReturn($newParams);

		$responseBody = json_encode(
			['access_token' => 'some access-token', 'id_token' => $idToken],
			JSON_THROW_ON_ERROR,
		);

		$mockHandler = new MockHandler([
			new Response(200, [], $responseBody)
		]);
		$handlerStack = HandlerStack::create($mockHandler);

		$this->provider->setHttpClient(new Client(['handler' => $handlerStack]));

		// AbstractProvider::getParsedResponse
	}
}
