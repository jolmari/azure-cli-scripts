using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using X509Certificate=Org.BouncyCastle.X509.X509Certificate;

namespace BouncyCastleHelpers;

public static class X509Certificate2Builder {

	/// <summary>
	///     Create a self-signed X509Certificate2 (RSA). The certificate contains the private key and
	///     the corresponding X.509 public key certificate.
	/// </summary>
	/// <param name="kid">Key identifier</param>
	/// <param name="subjectName">Subject name</param>
	/// <param name="issuerName">Issuer name</param>
	/// <param name="notBefore">Certificate activation date</param>
	/// <param name="notAfter">Certificate expiry date</param>
	/// <returns>Created certificate object</returns>
	public static X509Certificate2 GenerateSelfSignedRSACertificate(string kid,
		string subjectName, string issuerName, DateTimeOffset notBefore, DateTimeOffset notAfter) {
		
		// Generate a RSA 4096 bitkey pair
		var random = new SecureRandom();
		var keyPairGenerator = new RsaKeyPairGenerator();
		keyPairGenerator.Init(new KeyGenerationParameters(random, 4096));
		var keyPair = keyPairGenerator.GenerateKeyPair();

		// Define subject and issuer distinguished names
		var subjectDn = new X509Name(subjectName);
		var issuerDn = new X509Name(issuerName);

		// Generate the certificate
		var x509V3CertGen = new X509V3CertificateGenerator();
		var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), random);
		x509V3CertGen.SetSerialNumber(serialNumber);
		x509V3CertGen.SetIssuerDN(issuerDn);
		x509V3CertGen.SetNotBefore(notBefore.Date);
		x509V3CertGen.SetNotAfter(notAfter.Date);
		x509V3CertGen.SetSubjectDN(subjectDn);
		x509V3CertGen.SetPublicKey(keyPair.Public);

		// Define signature algorithm
		var signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", keyPair.Private, random);
		
		// Sign the certificate
		var certificate = x509V3CertGen.Generate(signatureFactory);

		// Convert the BouncyCastle certificate to a .NET certificate, including the private key.
		// This is done by using a Pkcs12Store to store the public and the private key.
		var store = new Pkcs12StoreBuilder().Build();
		var certificateEntry = new X509CertificateEntry(certificate);
		store.SetCertificateEntry(kid, certificateEntry); // keyId should be a unique alias for the certificate

		// Add the private key entry to the PKCS12 store
		store.SetKeyEntry(kid, new AsymmetricKeyEntry(keyPair.Private), new[] { certificateEntry });

		// Convert to byte array
		var stream = new MemoryStream();
		store.Save(stream, null, random);
		var convertedCertificateBytes = stream.ToArray();

		// Create an X509Certificate2 object from the PKCS12 data, including the private key
		return new X509Certificate2(
			convertedCertificateBytes,
			(string)null,
			X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet
		);
	}

	/// <summary>
	///     Convert a PEM-formatted X.509 certificate to an X509Certificate2 object.
	/// </summary>
	/// <param name="x509pem"></param>
	/// <returns></returns>
	public static X509Certificate2 ConvertPemToX509Certificate(string x509pem) {
		using var stringReader = new StringReader(x509pem);
		var pemObject = new PemReader(stringReader).ReadObject();
		return new X509Certificate2(DotNetUtilities.ToX509Certificate((X509Certificate)pemObject));
	}
}