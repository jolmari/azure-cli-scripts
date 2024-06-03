using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace JwtSecurityTokenSamples;

public static class JwtValidator {
	public static async Task<TokenValidationResult> Validate(
		JwtSecurityTokenHandler securityTokenHandler, 
		RSAParameters rsaParameters,
		string issuer, 
		string compactSignedToken,
		bool validateLifetime = false) {
		
		var validationResult = await securityTokenHandler
			.ValidateTokenAsync(compactSignedToken, new TokenValidationParameters {
				ValidateIssuer = true,
				ValidateLifetime = validateLifetime,
				ValidateAudience = false,
				ValidIssuer = issuer,
				ValidateIssuerSigningKey = true,
				IssuerSigningKey = new RsaSecurityKey(rsaParameters)
			});

		if (!validationResult.IsValid) {
			throw new SecurityTokenValidationException("Validation of Entity Statement token failed");
		}

		return validationResult;
	}
}