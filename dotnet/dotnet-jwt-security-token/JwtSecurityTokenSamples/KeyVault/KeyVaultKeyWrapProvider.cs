using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace JwtSecurityTokenSamples.KeyVault;

public class KeyVaultKeyWrapProvider : KeyWrapProvider {
	private readonly CryptographyClient cryptographyClient;

	public KeyVaultKeyWrapProvider(CryptographyClient cryptographyClient, KeyVaultRsaSecurityKey key, string algorithm) {
		this.cryptographyClient = cryptographyClient;
		Key = key;
		Algorithm = algorithm;
	}

	public override SecurityKey Key { get; }

	public override string Algorithm { get; }

	public override string Context {
		get => throw new NotImplementedException(); 
		set => throw new NotImplementedException();
	}

	public override byte[] WrapKey(byte[] keyBytes) {
		if (keyBytes == null || keyBytes.Length == 0) {
			throw new ArgumentNullException(nameof(keyBytes));
		}

		// Use the RSA object directly since we already have the public key
		var key = (KeyVaultRsaSecurityKey)Key;
		using var rsa = key.Key.Key.ToRSA();

		var result = cryptographyClient.WrapKey(GetAlgorithm(Algorithm), keyBytes);
		return result.EncryptedKey;
	}

	public override byte[] UnwrapKey(byte[] keyBytes) {
		if (keyBytes == null || keyBytes.Length == 0) {
			throw new ArgumentNullException(nameof(keyBytes));
		}

		var result = cryptographyClient.UnwrapKey(GetAlgorithm(Algorithm), keyBytes);
		return result.Key;
	}

	protected override void Dispose(bool disposing) {
	}

	private static KeyWrapAlgorithm GetAlgorithm(string algorithm) {
		return algorithm switch {
			SecurityAlgorithms.RsaOAEP => KeyWrapAlgorithm.RsaOaep,
			_ => throw new NotImplementedException()
		};
	}
}