using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using JwtSecurityTokenSamples;
using Microsoft.IdentityModel.Tokens;

// var securityAlgorithm = SecurityAlgorithms.RsaSha256;
//
// Console.WriteLine("Creating self-signed certificate...");
// var subjectDistinguishedName = "C=FI, ST=Uusimaa, L=Helsinki, O=Sample Oy, CN=www.sample.com";
// var issuerDistinguishedName = "C=FI, ST=Uusimaa, L=Helsinki, O=Sample Oy, CN=www.sample.com";
// var certificate = X509Certificate2Builder.GenerateSelfSignedRSACertificate("kid",
// 	subjectDistinguishedName, issuerDistinguishedName, DateTimeOffset.Now, DateTimeOffset.Now.AddMonths(60));
// Console.WriteLine("Self-signed certificate created.");
//
// Console.WriteLine("Building compact JWT entity statement token...");
// var compactToken = EntityStatementJwtSecurityTokenBuilder.BuildCompact(certificate, securityAlgorithm);
// Console.WriteLine("Compact JWT entity statement token created.");
// Console.WriteLine(compactToken);

var pemFile = File.ReadAllText(args[0]);
var token = File.ReadAllText(args[1]);
var issuer = args[2];

var x509Certificate = X509Certificate2Builder.ConvertPemToX509Certificate(pemFile);
var rsaParameters = x509Certificate.GetRSAPublicKey().ExportParameters(false);

Console.WriteLine("Validating JWT entity statement token...");
var securityTokenHandler = new JwtSecurityTokenHandler();
var result = await JwtValidator.Validate(securityTokenHandler, rsaParameters, issuer, token);

if (result.IsValid) {
	Console.WriteLine("JWT entity statement token is valid.");
} else {
	Console.WriteLine("JWT entity statement token is invalid.");
}