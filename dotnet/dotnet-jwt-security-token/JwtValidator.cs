using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace JwtSecurityTokenSamples;

public static class JwtValidator {
	public static async Task<TokenValidationResult> DecryptAndValidate(
		JsonWebTokenHandler jwtTokenHandler,
		string issuer,
		string encryptedAndSignedToken,
		X509Certificate2 signingCertificate,
		X509Certificate2 decryptionCertificate,
		bool validateLifetime = false) {

		var decryptedToken = jwtTokenHandler.DecryptToken(new JsonWebToken(encryptedAndSignedToken), new TokenValidationParameters {
			TokenDecryptionKey = new X509SecurityKey(decryptionCertificate)
		});

		if (decryptedToken == null) {
			throw new SecurityTokenDecryptionFailedException("Decryption of Entity Statement token failed");
		}

		var validationResult = await jwtTokenHandler
			.ValidateTokenAsync(decryptedToken, new TokenValidationParameters {
				ValidateIssuer = true,
				ValidateLifetime = validateLifetime,
				ValidateAudience = false,
				ValidIssuer = issuer,
				ValidateIssuerSigningKey = true,
				IssuerSigningKey = new X509SecurityKey(signingCertificate, SecurityAlgorithms.RsaSha256)
			});

		if (!validationResult.IsValid) {
			if (validationResult.Exception != null) {
				throw validationResult.Exception;
			}

			throw new SecurityTokenValidationException("Validation of Entity Statement token failed");
		}

		return validationResult;
	}


	public static async Task<TokenValidationResult> Validate(
		JsonWebTokenHandler jwtTokenHandler,
		string issuer,
		string compactSignedToken,
		X509Certificate2? signingCertificate = null,
		bool validateLifetime = false) {

		var validationResult = await jwtTokenHandler
			.ValidateTokenAsync(compactSignedToken, new TokenValidationParameters {
				ValidateIssuer = true,
				ValidateLifetime = validateLifetime,
				ValidateAudience = false,
				ValidIssuer = issuer,
				ValidateIssuerSigningKey = true,
				IssuerSigningKey = new X509SecurityKey(signingCertificate, SecurityAlgorithms.RsaSha256)
			});

		if (!validationResult.IsValid) {
			if (validationResult.Exception != null) {
				throw validationResult.Exception;
			}

			throw new SecurityTokenValidationException("Validation of Entity Statement token failed");
		}

		return validationResult;
	}
}