using System.Security.Cryptography;
using System.Text;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using FluentAssertions;
using JwtSecurityTokenSamples.KeyVault;
using Microsoft.IdentityModel.Tokens;
using Moq;
using JsonWebKey=Azure.Security.KeyVault.Keys.JsonWebKey;

namespace JwtSecurityTokenSamples.Tests;

public class KeyVaultKeySignatureProviderTests {
	
	private readonly KeyVaultKeySignatureProvider signatureProvider;
	private readonly Mock<CryptographyClient> mockCryptographyClient = new();

	public KeyVaultKeySignatureProviderTests() {
		using var rsa = RSA.Create();
		var key = new JsonWebKey(rsa);
		var mockKey = KeyModelFactory.KeyVaultKey(new KeyProperties("kid"), key);
		signatureProvider = new KeyVaultKeySignatureProvider(mockCryptographyClient.Object, new KeyVaultRsaSecurityKey(mockKey, "kid"), SecurityAlgorithms.RsaSha256);
	}

	[Fact]
	public void Sign_ShouldReturnTrueAndWriteSignatureToDestination_WhenSignatureSucceeds()
	{
		// Arrange
		var bytes = Encoding.UTF8.GetBytes("test");
		var data = new ReadOnlySpan<byte>(bytes);
		var destination = new Span<byte>(new byte[bytes.Length]);
		var signatureBytes = new byte[bytes.Length];
		
		mockCryptographyClient
			.Setup(x => x.SignData(It.IsAny<SignatureAlgorithm>(), It.IsAny<byte[]>(), It.IsAny<System.Threading.CancellationToken>()))
			.Returns(CryptographyModelFactory.SignResult("kid", signatureBytes));
		
		// Act
		var result = signatureProvider.Sign(data, destination , out var bytesWritten);
		
		// Assert
		result.Should().BeTrue();
		destination.ToArray().Should().BeEquivalentTo(signatureBytes);
		bytesWritten.Should().Be(signatureBytes.Length);
	}
	
	[Fact]
	public void Sign_ShouldReturnFalse_WhenSignatureFails()
	{
		// Arrange
		var bytes = Encoding.UTF8.GetBytes("test");
		var data = new ReadOnlySpan<byte>(bytes);
		var destination = new Span<byte>(new byte[bytes.Length]);
		
		// Act
		var result = signatureProvider.Sign(data, destination, out var bytesWritten);
		
		// Assert
		result.Should().BeFalse();
		bytesWritten.Should().Be(0);
	}
	
	[Fact]
	public void Sign_ShouldThrowException_WhenInputIsNull()
	{
		// Arrange
		var bytes = Encoding.UTF8.GetBytes("test");
		var span = new ReadOnlySpan<byte>(bytes);
		
		// Act & Assert
		Assert.Throws<ArgumentNullException>(() => signatureProvider.Sign(null, bytes , out var _));
	}
	
	[Fact]
	public void Sign_ShouldReturnSignature_WhenCalledWithValidParameters() {
		// Arrange
		var data = Encoding.UTF8.GetBytes("test");
		
		// Act & Assert
		Assert.Throws<NotImplementedException>(() => signatureProvider.Sign(data));
	}
	
	[Fact]
	public void Verify_ShouldReturnTrue_WhenSignatureIsValid() {
		// Arrange
		var data = Encoding.UTF8.GetBytes("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ");
		var signature = Encoding.UTF8.GetBytes("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
		
		mockCryptographyClient
			.Setup(x => x.VerifyData(SecurityAlgorithms.RsaSha256, It.IsAny<byte[]>(), It.IsAny<byte[]>(), It.IsAny<System.Threading.CancellationToken>()))
			.Returns(CryptographyModelFactory.VerifyResult("key", true));
		
		// Act
		var result = signatureProvider.Verify(data, signature);
		
		// Assert
		result.Should().BeTrue();
	}
	
	[Fact]
	public void Verify_ShouldReturnFalse_WhenSignatureIsInvalid() {
		// Arrange
		var data = Encoding.UTF8.GetBytes("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ");
		var signature = Encoding.UTF8.GetBytes("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
		
		mockCryptographyClient
			.Setup(x => x.VerifyData(SecurityAlgorithms.RsaSha256, It.IsAny<byte[]>(), It.IsAny<byte[]>(), It.IsAny<System.Threading.CancellationToken>()))
			.Returns(CryptographyModelFactory.VerifyResult("key", false));
		
		// Act
		var result = signatureProvider.Verify(data, signature);
		
		// Assert
		result.Should().BeFalse();
	}
	
	[Fact]
	public void Verify_ShouldThrowException_WhenInputIsNull() {
		// Arrange
		var data = Encoding.UTF8.GetBytes("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ");
		var signature = Encoding.UTF8.GetBytes("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
		
		// Act & Assert
		Assert.Throws<ArgumentNullException>(() => signatureProvider.Verify(null, signature));
	}
	
	[Fact]
	public void Verify_ShouldThrowException_WhenSignatureIsNull() {
		// Arrange
		var data = Encoding.UTF8.GetBytes("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ");
		var signature = Encoding.UTF8.GetBytes("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
		
		// Act & Assert
		Assert.Throws<ArgumentNullException>(() => signatureProvider.Verify(data, null));
	}
	
	[Fact]
	public void VerifyWithOffsets_ShouldReturnTrue_WhenSignatureIsValid() {
		// Arrange
		var data = Encoding.UTF8.GetBytes("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ");
		var signature = Encoding.UTF8.GetBytes("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
		
		mockCryptographyClient
			.Setup(x => x.VerifyData(SecurityAlgorithms.RsaSha256, It.IsAny<byte[]>(), It.IsAny<byte[]>(), It.IsAny<System.Threading.CancellationToken>()))
			.Returns(CryptographyModelFactory.VerifyResult("key", true));
		
		// Act
		var result = signatureProvider.Verify(data, 0, data.Length, signature, 0, signature.Length);
		
		// Assert
		result.Should().BeTrue();
	}
	
	[Fact]
	public void VerifyWithOffsets_ShouldReturnTrue_WhenSignatureIsValid_AndInputLengthsNotMatching() {
		// Arrange
		var data = Encoding.UTF8.GetBytes("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ");
		var signature = Encoding.UTF8.GetBytes("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
		
		mockCryptographyClient
			.Setup(x => x.VerifyData(SecurityAlgorithms.RsaSha256, It.IsAny<byte[]>(), It.IsAny<byte[]>(), It.IsAny<System.Threading.CancellationToken>()))
			.Returns(CryptographyModelFactory.VerifyResult("key", true));
		
		// Act
		var result = signatureProvider.Verify(data, 0, data.Length - 1, signature, 0, signature.Length - 1);
		
		// Assert
		result.Should().BeTrue();
	}
	
	[Fact]
	public void VerifyWithOffsets_ShouldThrowException_WhenInputIsNull() {
		// Arrange
		var data = Encoding.UTF8.GetBytes("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ");
		var signature = Encoding.UTF8.GetBytes("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
		
		// Act & Assert
		Assert.Throws<ArgumentNullException>(() => signatureProvider.Verify(null, 0, data.Length, signature, 0, signature.Length));
	}
	
	[Fact]
	public void VerifyWithOffsets_ShouldThrowException_WhenSignatureIsNull() {
		// Arrange
		var data = Encoding.UTF8.GetBytes("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ");
		var signature = Encoding.UTF8.GetBytes("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
		
		// Act & Assert
		Assert.Throws<ArgumentNullException>(() => signatureProvider.Verify(data, 0, data.Length, null, 0, signature.Length));
	}
	
	[Fact]
	public void VerifyWithOffsets_ShouldThrowException_WhenInputOffsetIsLessThanZero() {
		// Arrange
		var data = Encoding.UTF8.GetBytes("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ");
		var signature = Encoding.UTF8.GetBytes("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
		
		// Act & Assert
		Assert.Throws<ArgumentException>(() => signatureProvider.Verify(data, -1, data.Length, signature, 0, signature.Length));
	}
	
	[Fact]
	public void VerifyWithOffsets_ShouldThrowException_WhenInputLengthIsLessThanOne() {
		// Arrange
		var data = Encoding.UTF8.GetBytes("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ");
		var signature = Encoding.UTF8.GetBytes("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
		
		// Act & Assert
		Assert.Throws<ArgumentException>(() => signatureProvider.Verify(data, 0, 0, signature, 0, signature.Length));
	}
	
	[Fact]
	public void VerifyWithOffsets_ShouldThrowException_WhenInputOffsetPlusInputLengthIsGreaterThanInputArrayLength() {
		// Arrange
		var data = Encoding.UTF8.GetBytes("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ");
		var signature = Encoding.UTF8.GetBytes("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
		
		// Act & Assert
		Assert.Throws<ArgumentException>(() => signatureProvider.Verify(data, 0, data.Length + 1, signature, 0, signature.Length));
	}
	
	[Fact]
	public void VerifyWithOffsets_ShouldThrowException_WhenSignatureOffsetIsLessThanZero() {
		// Arrange
		var data = Encoding.UTF8.GetBytes("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ");
		var signature = Encoding.UTF8.GetBytes("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
		
		// Act & Assert
		Assert.Throws<ArgumentException>(() => signatureProvider.Verify(data, 0, data.Length, signature, -1, signature.Length));
	}
	
	[Fact]
	public void VerifyWithOffsets_ShouldThrowException_WhenSignatureLengthIsLessThanOne() {
		// Arrange
		var data = Encoding.UTF8.GetBytes("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ");
		var signature = Encoding.UTF8.GetBytes("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
		
		// Act & Assert
		Assert.Throws<ArgumentException>(() => signatureProvider.Verify(data, 0, data.Length, signature, 0, 0));
	}
	
	[Fact]
	public void VerifyWithOffsets_ShouldThrowException_WhenSignatureOffsetPlusSignatureLengthIsGreaterThanSignatureArrayLength() {
		// Arrange
		var data = Encoding.UTF8.GetBytes("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ");
		var signature = Encoding.UTF8.GetBytes("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
		
		// Act & Assert
		Assert.Throws<ArgumentException>(() => signatureProvider.Verify(data, 0, data.Length, signature, 0, signature.Length + 1));
	}
}