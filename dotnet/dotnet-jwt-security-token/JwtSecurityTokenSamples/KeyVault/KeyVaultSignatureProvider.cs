using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace JwtSecurityTokenSamples.KeyVault;

public class KeyVaultKeySignatureProvider : SignatureProvider {
	private readonly CryptographyClient cryptographyClient;

	public KeyVaultKeySignatureProvider(
		CryptographyClient cryptographyClient,
		KeyVaultRsaSecurityKey key,
		string algorithm)
		: base(key, algorithm) {
		this.cryptographyClient = cryptographyClient;
	}

	public override byte[] Sign(byte[] input) => throw new NotImplementedException();
	public override bool Sign(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten) {
		if (data == null || data.Length == 0) {
			throw new ArgumentNullException(nameof(data));
		}

		var result = cryptographyClient.SignData(GetKeyVaultAlgorithm(Algorithm), data.ToArray());
		
		if(result == null || result.Signature.Length == 0) {
			bytesWritten = 0;
			return false;
		}
		
		result.Signature.CopyTo(destination);		
		bytesWritten = result.Signature.Length;
		
		return true;
	}

	public override bool Verify(byte[] input, byte[] signature) {
		if (input == null || input.Length == 0) {
			throw new ArgumentNullException(nameof(input));
		}

		if (signature == null || signature.Length == 0) {
			throw new ArgumentNullException(nameof(signature));
		}

		// Use the RSA object directly since we already have the public key
		var key = (KeyVaultRsaSecurityKey)Key;
		using var rsa = key.Key.Key.ToRSA();

		var result = cryptographyClient.VerifyData(GetKeyVaultAlgorithm(Algorithm), input, signature);
		return result.IsValid;
	}

	public override bool Verify(byte[] input, int inputOffset, int inputLength, byte[] signature, int signatureOffset, int signatureLength) {
		if (input == null || input.Length == 0) {
			throw new ArgumentNullException(nameof(input));
		}
		
		if (signature == null || signature.Length == 0) {
			throw new ArgumentNullException(nameof(signature));
		}
		
		if (inputOffset < 0) {
			throw new ArgumentException("inputOffset must be greater than 0", nameof(inputOffset));
		}
		
		if (inputLength < 1) {
			throw new ArgumentException("inputLength must be greater than 1", nameof(inputLength));
		}
		
		if (inputOffset + inputLength > input.Length) {
			throw new ArgumentException("inputOffset + inputLength must be greater than input array length");
		}
		
		if (signatureOffset < 0) {
			throw new ArgumentException("signatureOffset must be greater than 0", nameof(signatureOffset));
		}
		
		if (signatureLength < 1) {
			throw new ArgumentException("signatureLength must be greater than 1", nameof(signatureLength));
		}
		
		if (signatureOffset + signatureLength > signature.Length) {
			throw new ArgumentException("signatureOffset + signatureLength must be greater than signature array length");
		}
		
		// Basically the input or signature array could contain a bunch of zeroes that we don't want
		// in the signature calculation, as that would affect the result.
		// In testing, inputLength < input.Length and signatureLength == signature.Length.
		// The offsets were zero in both cases.

		byte[] actualInput;
		if (input.Length == inputLength)
		{
			actualInput = input;
		}
		else
		{
			var temp = new byte[inputLength];
			Array.Copy(input, inputOffset, temp, 0, inputLength);
			actualInput = temp;
		}

		byte[] actualSignature;
		if (signature.Length == signatureLength) {
			actualSignature = signature;
		}
		else {
			var temp = new byte[signatureLength];
			Array.Copy(signature, signatureOffset, temp, 0, signatureLength);
			actualSignature = temp;
		}

		// Use the RSA object directly since we already have the public key
		var key = (KeyVaultRsaSecurityKey)Key;
		using var rsa = key.Key.Key.ToRSA();

		return Verify(actualInput, actualSignature);
	}

	protected override void Dispose(bool disposing) {
	}

	private static SignatureAlgorithm GetKeyVaultAlgorithm(string algorithm) {
		return algorithm switch {
			SecurityAlgorithms.RsaSha256 => SignatureAlgorithm.RS256,
			SecurityAlgorithms.RsaSha384 => SignatureAlgorithm.RS384,
			SecurityAlgorithms.RsaSha512 => SignatureAlgorithm.RS512,
			_ => throw new NotImplementedException()
		};
	}
}