using System.Collections;
using System.Security.Cryptography;
using Azure.Security.KeyVault.Keys;
using FluentAssertions;
using JwtSecurityTokenSamples.KeyVault;
using Microsoft.IdentityModel.Tokens;
using JsonWebKey=Azure.Security.KeyVault.Keys.JsonWebKey;

namespace JwtSecurityTokenSamples.Tests;

public class KeyVaultRsaSecurityKeyTests {
	[Fact]
	public void KeyVaultRsaSecurityKey_ShouldMapProperties() {
		// Arrange
		using var rsa = RSA.Create();
		var jsonWebKey = new JsonWebKey(rsa);
		var key = KeyModelFactory.KeyVaultKey(new KeyProperties("kid"), jsonWebKey);
		var externalId = "your-external-id";

		// Act
		var result = new KeyVaultRsaSecurityKey(key, externalId);

		// Assert
		var thumbprint = new RsaSecurityKey(rsa).ComputeJwkThumbprint();

		result.Key.Should().Be(key);
		result.KeySize.Should().Be(new BitArray(key.Key.N).Length);
		result.KeyId.Should().Be(externalId);
		result.KeyName.Should().Be(key.Properties.Name);
		result.KeyVersion.Should().Be(key.Properties.Version);
		result.Thumbprint.Should().Be(Base64UrlEncoder.Encode(thumbprint));
		result.HasPrivateKey.Should().BeTrue();
		result.PrivateKeyStatus.Should().Be(PrivateKeyStatus.Exists);
	}
}