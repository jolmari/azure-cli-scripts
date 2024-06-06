using System.Security.Cryptography.X509Certificates;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using JwtSecurityTokenSamples;
using JwtSecurityTokenSamples.KeyVault;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

var configuration = new ConfigurationBuilder()
	.AddUserSecrets<Program>()
	.Build();

var keyVaultUri = configuration["KeyVaultUri"];
var signingKeyId = configuration["SigningKeyId"];
var encryptionKeyId = configuration["EncryptionKeyId"];

var signingAlgorithm = SecurityAlgorithms.RsaSha256;
var cekEncryptionAlgorithm = SecurityAlgorithms.RsaOAEP;
var jwtEncryptionAlgorithm = SecurityAlgorithms.Aes256CbcHmacSha512;

var signingKeyExternalKid = "/keys/signing-key";
var encryptionKeyExternalKeyId = "/keys/encryption-key";

var signingCertificate = CreateSelfSignedCertificate();

var keyClient = new KeyClient(new Uri(keyVaultUri), new DefaultAzureCredential());

var signingCryptoProviderFactory = new CryptoProviderFactory {
	CustomCryptoProvider = new KeyVaultCryptoProvider(keyClient)
};

var signingKey = await keyClient.GetKeyAsync(signingKeyId);
var encryptionKey = await keyClient.GetKeyAsync(encryptionKeyId);

var keyVaultSigningKey = new KeyVaultRsaSecurityKey(signingKey, signingKeyExternalKid) {
	CryptoProviderFactory = signingCryptoProviderFactory
};

var keyVaultWrapKey = new KeyVaultRsaSecurityKey(encryptionKey, encryptionKeyExternalKeyId) {
	CryptoProviderFactory = signingCryptoProviderFactory
};

var handler = new JsonWebTokenHandler();

var token = handler.CreateToken(new SecurityTokenDescriptor {
	Issuer = "https://test.fi",
	SigningCredentials = new SigningCredentials(keyVaultSigningKey, signingAlgorithm),
	EncryptingCredentials = new EncryptingCredentials(keyVaultWrapKey, cekEncryptionAlgorithm, jwtEncryptionAlgorithm)
});

var validationResult = await handler.ValidateTokenAsync(token, new TokenValidationParameters {
	ValidateIssuer = true,
	ValidateAudience = false,
	ValidIssuer = "https://test.fi",
	IssuerSigningKey = keyVaultSigningKey,
	TokenDecryptionKey = keyVaultWrapKey
});

Console.WriteLine(token);

if (!validationResult.IsValid) {
	throw validationResult.Exception;
}


// var issuer = "https://test.fi";
//
// var encryptionCertificate = CreateSelfSignedCertificate();
//
// Console.WriteLine("Building compact JWT entity statement token...");
// var compactToken = JsonTokenBuilder.BuildJwt(signingCertificate, signingAlgorithm, issuer);
// Console.WriteLine("Compact JWT entity statement token created.");
// Console.WriteLine(compactToken);
//
// Console.WriteLine("Validating JWT entity statement token...");
// var firstSecurityTokenHandler = new JsonWebTokenHandler();
// var result = await JwtValidator.Validate(firstSecurityTokenHandler, issuer, compactToken, signingCertificate, true);
//
// if (result.IsValid) {
// 	Console.WriteLine("JWT entity statement token is valid.");
// }
// else {
// 	Console.WriteLine("JWT entity statement token is invalid.");
// }
//
// var encryptedToken = JsonTokenBuilder.BuildJweWrappedJwt(signingCertificate, encryptionCertificate,
// 	signingAlgorithm, cekEncryptionAlgorithm, jwtEncryptionAlgorithm, issuer);
//
// var jweValidationResult = await JwtValidator.DecryptAndValidate(firstSecurityTokenHandler, issuer, encryptedToken,
// 	signingCertificate, encryptionCertificate, true);
//
X509Certificate2 CreateSelfSignedCertificate() {

	Console.WriteLine("Creating self-signed certificate...");
	var subjectDistinguishedName = "C=FI, ST=Uusimaa, L=Helsinki, O=Sample Oy, CN=www.sample.com";
	var issuerDistinguishedName = "C=FI, ST=Uusimaa, L=Helsinki, O=Sample Oy, CN=www.sample.com";
	var x509Certificate2 = X509Certificate2Builder.GenerateSelfSignedRSACertificate("kid",
		subjectDistinguishedName, issuerDistinguishedName, DateTimeOffset.Now, DateTimeOffset.Now.AddMonths(60));
	Console.WriteLine("Self-signed certificate created.");
	return x509Certificate2;
}