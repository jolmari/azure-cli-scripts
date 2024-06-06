using System.Collections;
using System.Security.Cryptography;
using Azure.Security.KeyVault.Keys;
using Microsoft.IdentityModel.Tokens;

namespace JwtSecurityTokenSamples.KeyVault;

public class KeyVaultRsaSecurityKey : AsymmetricSecurityKey {
	public KeyVaultRsaSecurityKey() {
	}

	public KeyVaultRsaSecurityKey(KeyVaultKey key, string keyExternalName) {
		Key = key;
		KeyId = keyExternalName;
	}

	public KeyVaultKey Key { get; }
	public override sealed string KeyId { get; set; }
	public override int KeySize => new BitArray(Key.Key.N).Length;

	public virtual string KeyName => Key.Properties.Name;
	public virtual string KeyVersion => Key.Properties.Version;
	public virtual string Thumbprint => GetKeyId(Key);

	[Obsolete("HasPrivateKey method is deprecated, please use PrivateKeyStatus instead.")]
	public override bool HasPrivateKey => true;
	public override PrivateKeyStatus PrivateKeyStatus => PrivateKeyStatus.Exists;

	private static string GetKeyId(KeyVaultKey key) {
		using var rsa = key.Key.ToRSA();

		if (rsa == null) {
			throw new CryptographicException("Key is not an RSA key.");
		}

		var rsaKey = new RsaSecurityKey(rsa);
		var thumbprint = rsaKey.ComputeJwkThumbprint();
		return Base64UrlEncoder.Encode(thumbprint);
	}
}