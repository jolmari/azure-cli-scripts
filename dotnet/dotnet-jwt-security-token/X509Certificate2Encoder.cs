using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;

namespace BouncyCastleHelpers;

public static class X509Certificate2Encoder {
	public static string ConvertBase64DerToPem(string base64der) {
		var bytes = Convert.FromBase64String(base64der);
		var x509Certificate = new X509CertificateParser().ReadCertificate(bytes);

		// Encode the certificate in PEM format
		using var stringWriter = new StringWriter();
		var pemWriter = new PemWriter(stringWriter);
		pemWriter.WriteObject(x509Certificate);
		return stringWriter.ToString();
	}
}