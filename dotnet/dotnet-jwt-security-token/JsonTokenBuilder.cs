using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace JwtSecurityTokenSamples;

public static class JsonTokenBuilder {

	/// <summary>
	///     Builds a compact signed JWT token with the given certificate and security algorithm.
	/// </summary>
	/// <param name="certificate">Token signing credentials with private key</param>
	/// <param name="securityAlgorithm">Security algorithm used to sign the token</param>
	/// <param name="issuer"></param>
	/// <returns></returns>
	public static string BuildJwt(X509Certificate2 certificate, string securityAlgorithm, string issuer) {

		// Create the security key from the x509 certificate and set a custom key identifier which will appear in the
		// JWT header as the 'kid' claim.
		var x509SecurityKey = new X509SecurityKey(certificate) {
			KeyId = "jwt-signing-key"
		};
		var x509SigningCredentials = new SigningCredentials(x509SecurityKey, securityAlgorithm);

		var securityTokenHandler = new JsonWebTokenHandler();
		return securityTokenHandler.CreateToken(new SecurityTokenDescriptor {
			Issuer = issuer,
			SigningCredentials = x509SigningCredentials
		});
	}

	/// <summary>
	///     Builds a compact signed JWE-encrypted JWT token with the given certificate and security algorithm.
	/// </summary>
	/// <param name="signingCertificate">Token signing credentials with private key</param>
	/// <param name="encryptionCertificate"></param>
	/// <param name="signingAlgorithm"></param>
	/// <param name="cekEncryptionAlgorithm">Security algorithm used to sign the token</param>
	/// <param name="jwtEncryptionAlgorithm"></param>
	/// <param name="issuer"></param>
	/// <returns></returns>
	public static string BuildJweWrappedJwt(X509Certificate2 signingCertificate, X509Certificate2 encryptionCertificate,
		string signingAlgorithm, string cekEncryptionAlgorithm, string jwtEncryptionAlgorithm, string issuer) {

		// Create the security key from the x509 certificate and set a custom key identifier which will appear in the
		// JWT header as the 'kid' claim.
		var x509SecurityKey = new X509SecurityKey(signingCertificate) {
			KeyId = "jwt-signing-key"
		};

		// Use the private signing key part of the X509 certificate to sign the token.
		var x509SigningCredentials = new SigningCredentials(x509SecurityKey, signingAlgorithm);

		var securityTokenHandler = new JsonWebTokenHandler();

		// Use the public encryption key to encrypt the token.
		var encryptingCredentials = new EncryptingCredentials(
			new X509SecurityKey(encryptionCertificate) {
				KeyId = "jwe-encryption-key"
			},
			cekEncryptionAlgorithm,
			jwtEncryptionAlgorithm);

		return securityTokenHandler.CreateToken(new SecurityTokenDescriptor {
			Issuer = issuer,
			SigningCredentials = x509SigningCredentials,
			EncryptingCredentials = encryptingCredentials
		});
	}
}