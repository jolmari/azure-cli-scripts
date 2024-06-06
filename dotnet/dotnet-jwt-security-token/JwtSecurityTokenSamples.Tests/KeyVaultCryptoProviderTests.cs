using Azure.Security.KeyVault.Keys;
using FluentAssertions;
using JwtSecurityTokenSamples.KeyVault;
using Microsoft.IdentityModel.Tokens;
using Moq;

namespace JwtSecurityTokenSamples.Tests;

public class KeyVaultCryptoProviderTests {
	private readonly KeyVaultCryptoProvider cryptoProvider;
	private readonly Mock<KeyClient> mockKeyClient = new();
	public KeyVaultCryptoProviderTests() {
		cryptoProvider = new KeyVaultCryptoProvider(mockKeyClient.Object);
	}

	[Fact]
	public void Create_ShouldReturnKeyVaultKeyWrapProvider_WhenCalledWithSupportedAlgorithmAndArguments() {
		// Arrange
		var mockKey = new Mock<KeyVaultRsaSecurityKey>();
		mockKey.Setup(m => m.KeyName).Returns("testKeyName");
		mockKey.Setup(m => m.KeyVersion).Returns("testKeyVersion");

		// Act
		var result = cryptoProvider.Create(SecurityAlgorithms.RsaOAEP, mockKey.Object);

		// Assert
		result.Should().BeOfType<KeyVaultKeyWrapProvider>();
	}

	[Theory]
	[InlineData(SecurityAlgorithms.RsaSha256)]
	[InlineData(SecurityAlgorithms.RsaSha384)]
	[InlineData(SecurityAlgorithms.RsaSha512)]
	public void Create_ShouldReturnKeyVaultKeySignatureProvider_WhenCalledWithSupportedAlgorithmAndArguments(string algorithm) {
		// Arrange
		var mockKey = new Mock<KeyVaultRsaSecurityKey>();
		mockKey.Setup(m => m.KeyName).Returns("testKeyName");
		mockKey.Setup(m => m.KeyVersion).Returns("testKeyVersion");

		// Act
		var result = cryptoProvider.Create(algorithm, mockKey.Object);

		// Assert
		result.Should().BeOfType<KeyVaultKeySignatureProvider>();
	}

	[Fact]
	public void Release_ShouldDisposeObject_WhenCalledWithDisposableObject() {
		// Arrange
		var mockCryptoInstance = new Mock<IDisposable>();

		// Act
		cryptoProvider.Release(mockCryptoInstance.Object);

		// Assert
		mockCryptoInstance.Verify(m => m.Dispose(), Times.Once);
	}

	[Fact]
	public void Create_ShouldThrowArgumentException_WhenCalledWithUnsupportedAlgorithm() {
		// Arrange
		var mockKey = new Mock<KeyVaultRsaSecurityKey>();
		mockKey.Setup(m => m.KeyName).Returns("testKeyName");
		mockKey.Setup(m => m.KeyVersion).Returns("testKeyVersion");

		// Act
		var act = () => cryptoProvider.Create("unsupportedAlgorithm", mockKey.Object);

		// Assert
		act.Should().Throw<ArgumentException>();
	}

	[Fact]
	public void IsSupportedAlgorithm_ShouldReturnTrue_OnSupportedSymmetricAlgorithm() {
		// Arrange
		var symmetricKey = new SymmetricSecurityKey(new byte[16]);

		// Act
		var result = cryptoProvider.IsSupportedAlgorithm(SecurityAlgorithms.Aes128CbcHmacSha256, symmetricKey);

		// Assert
		result.Should().BeTrue();
	}

	[Fact]
	public void Create_ShouldReturnAuthenticatedEncryptionProvider_OnSupportedSymmetricAlgorithm() {
		// Arrange
		var symmetricKey = new SymmetricSecurityKey(new byte[16]);

		// Act
		var result = cryptoProvider.Create(SecurityAlgorithms.Aes128CbcHmacSha256, symmetricKey);

		// Assert
		result.Should().BeOfType<AuthenticatedEncryptionProvider>();
	}

	[Theory]
	[InlineData(SecurityAlgorithms.RsaOAEP, true)]
	[InlineData(SecurityAlgorithms.RsaSha256, true)]
	[InlineData(SecurityAlgorithms.RsaSha384, true)]
	[InlineData(SecurityAlgorithms.RsaSha512, true)]
	[InlineData("unsupported", false)]
	public void IsSupportedAlgorithm_ShouldReturnCorrectResult_OnGivenAsymmetricAlgorithms(string algorithm, bool expected) {
		// Arrange
		var mockKey = new Mock<KeyVaultRsaSecurityKey>();
		mockKey.Setup(m => m.KeyName).Returns("testKeyName");
		mockKey.Setup(m => m.KeyVersion).Returns("testKeyVersion");

		// Act
		var result = cryptoProvider.IsSupportedAlgorithm(algorithm, mockKey);

		// Assert
		result.Should().Be(expected);
	}
}