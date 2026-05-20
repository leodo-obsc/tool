using iTextSharp.text.pdf.security;

namespace SignService.Common.HashSignature.Common;

public class ExternalSignatureImpl : IExternalSignature
{
	private string _hashAlgorithm;

	private string _encryptionAlgorithm;

	private byte[] _signature;

	public ExternalSignatureImpl(string hash, string encrypt, byte[] signature)
	{
		_hashAlgorithm = hash;
		_encryptionAlgorithm = encrypt;
		_signature = signature;
	}

	public string GetEncryptionAlgorithm()
	{
		return _hashAlgorithm;
	}

	public string GetHashAlgorithm()
	{
		return _encryptionAlgorithm;
	}

	public byte[] Sign(byte[] message)
	{
		return _signature;
	}
}
