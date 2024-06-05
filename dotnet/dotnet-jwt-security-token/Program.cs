using System.Security.Cryptography.X509Certificates;
using JwtSecurityTokenSamples;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

var signingAlgorithm = SecurityAlgorithms.RsaSha256;
var cekEncryptionAlgorithm = SecurityAlgorithms.RsaOAEP;
var jwtEncryptionAlgorithm = SecurityAlgorithms.Aes256CbcHmacSha512;
var issuer = "https://test.fi";

var signingCertificate = CreateSelfSignedCertificate();
var encryptionCertificate = CreateSelfSignedCertificate();

Console.WriteLine("Building compact JWT entity statement token...");
var compactToken = JsonTokenBuilder.BuildJwt(signingCertificate, signingAlgorithm, issuer);
Console.WriteLine("Compact JWT entity statement token created.");
Console.WriteLine(compactToken);

Console.WriteLine("Validating JWT entity statement token...");
var firstSecurityTokenHandler = new JsonWebTokenHandler();
var result = await JwtValidator.Validate(firstSecurityTokenHandler, issuer, compactToken, signingCertificate, true);

if (result.IsValid) {
	Console.WriteLine("JWT entity statement token is valid.");
}
else {
	Console.WriteLine("JWT entity statement token is invalid.");
}

var encryptedToken = JsonTokenBuilder.BuildJweWrappedJwt(signingCertificate, encryptionCertificate, 
	signingAlgorithm, cekEncryptionAlgorithm, jwtEncryptionAlgorithm, issuer);

var jweValidationResult = await JwtValidator.DecryptAndValidate(firstSecurityTokenHandler, issuer, encryptedToken, 
	signingCertificate, encryptionCertificate, true);

X509Certificate2 CreateSelfSignedCertificate() {

	Console.WriteLine("Creating self-signed certificate...");
	var subjectDistinguishedName = "C=FI, ST=Uusimaa, L=Helsinki, O=Sample Oy, CN=www.sample.com";
	var issuerDistinguishedName = "C=FI, ST=Uusimaa, L=Helsinki, O=Sample Oy, CN=www.sample.com";
	var x509Certificate2 = X509Certificate2Builder.GenerateSelfSignedRSACertificate("kid",
		subjectDistinguishedName, issuerDistinguishedName, DateTimeOffset.Now, DateTimeOffset.Now.AddMonths(60));
	Console.WriteLine("Self-signed certificate created.");
	return x509Certificate2;
}