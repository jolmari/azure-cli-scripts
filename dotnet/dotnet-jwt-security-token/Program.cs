using BouncyCastleHelpers;
using Microsoft.IdentityModel.Tokens;

var securityAlgorithm = SecurityAlgorithms.RsaSha256;

Console.WriteLine("Creating self-signed certificate...");
var subjectDistinguishedName = "C=FI, ST=Uusimaa, L=Helsinki, O=Sample Oy, CN=www.sample.com";
var issuerDistinguishedName = "C=FI, ST=Uusimaa, L=Helsinki, O=Sample Oy, CN=www.sample.com";
var certificate = X509Certificate2Builder.GenerateSelfSignedRSACertificate("kid",
	subjectDistinguishedName, issuerDistinguishedName, DateTimeOffset.Now, DateTimeOffset.Now.AddMonths(60));
Console.WriteLine("Self-signed certificate created.");

Console.WriteLine("Building compact JWT entity statement token...");
var compactToken = EntityStatementJwtSecurityTokenBuilder.BuildCompact(certificate, securityAlgorithm);
Console.WriteLine("Compact JWT entity statement token created.");
Console.WriteLine(compactToken);