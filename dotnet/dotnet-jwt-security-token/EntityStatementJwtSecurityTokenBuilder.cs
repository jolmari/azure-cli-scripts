using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace JwtSecurityTokenSamples;

public static class EntityStatementJwtSecurityTokenBuilder {
	
	/// <summary>
	/// Builds a compact JWT entity statement token with the given certificate and security algorithm.
	/// <a href="https://openid.net/specs/openid-connect-federation-1_0-21.html#name-entity-statement">
	/// OpenId Connect Federation entity statement spec</a>
	/// </summary>
	/// <param name="certificate">Token signing credentials with private key</param>
	/// <param name="securityAlgorithm">Security algorithm used to sign the token</param>
	/// <returns></returns>
	public static string BuildCompact(X509Certificate2 certificate, string securityAlgorithm) {

		// Create the security key from the x509 certificate and set a custom key identifier which will appear in the
		// JWT header as the 'kid' claim.
		var x509SecurityKey = new X509SecurityKey(certificate) {
			KeyId = "jwt-signing-key"
		};
		var x509SigningCredentials = new SigningCredentials(x509SecurityKey, securityAlgorithm);
		
		var securityTokenHandler = new JwtSecurityTokenHandler();
		var token = securityTokenHandler.CreateJwtSecurityToken(new SecurityTokenDescriptor {
			SigningCredentials = x509SigningCredentials
		});
		
		return securityTokenHandler.WriteToken(token);
	}
}