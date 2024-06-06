using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace JwtSecurityTokenSamples.KeyVault;

public class KeyVaultCryptoProvider : ICryptoProvider {

	private readonly KeyClient _keyClient;

	public KeyVaultCryptoProvider(KeyClient keyClient)
	{
		_keyClient = keyClient;
	}

	public bool IsSupportedAlgorithm(string algorithm, params object[] args)
	{
		if (algorithm == SecurityAlgorithms.Aes128CbcHmacSha256 && args.Length > 0 && args[0] is SymmetricSecurityKey)
		{
			return true;
		}

		if (algorithm == SecurityAlgorithms.RsaOAEP)
		{
			return true;
		}

		if (algorithm == SecurityAlgorithms.RsaSha256 || algorithm == SecurityAlgorithms.RsaSha384 || algorithm == SecurityAlgorithms.RsaSha512)
		{
			return true;
		}

		return false;
	}

	public object Create(string algorithm, params object[] args)
	{
		// The framework classes always call IsSupportedAlgorithm first.
		// So we can expect algorithm and args to have sensible values here.
		
		if (algorithm == SecurityAlgorithms.Aes128CbcHmacSha256
		    && args.Length > 0
		    && args[0] is SymmetricSecurityKey symmetricKey)
		{
			return new AuthenticatedEncryptionProvider(symmetricKey, algorithm);
		}
		
		if (args.Length > 0 && args[0] is KeyVaultRsaSecurityKey rsaKey)
		{
			if (algorithm == SecurityAlgorithms.RsaOAEP)
			{
				//var willUnwrap = (bool)args[1];
				// return new KeyVaultKeyWrapProvider(GetCryptographyClient(rsaKey), rsaKey, algorithm);
			}

			if (algorithm == SecurityAlgorithms.RsaSha256 || algorithm == SecurityAlgorithms.RsaSha384 || algorithm == SecurityAlgorithms.RsaSha512)
			{
				//var willCreateSignatures = (bool)args[1];
				return new KeyVaultKeySignatureProvider(GetCryptographyClient(rsaKey), rsaKey, algorithm);
			}
		}

		throw new ArgumentException($"Unsupported algorithm: {algorithm}, or invalid arguments given", nameof(algorithm));
	}

	public void Release(object cryptoInstance)
	{
	}
	
	private CryptographyClient GetCryptographyClient(KeyVaultRsaSecurityKey key)
	{
		return _keyClient.GetCryptographyClient(key.KeyName, key.KeyVersion);
	}
}