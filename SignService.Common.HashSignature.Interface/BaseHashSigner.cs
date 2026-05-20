using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using SignService.Common.HashSignature.Common;

namespace SignService.Common.HashSignature.Interface;

public class BaseHashSigner
{
	public enum LTV_Level
	{
		B,
		T,
		LT,
		LTA
	}

	protected string HASH_ALGORITHM = "SHA1";

	protected static readonly string ENCRYPT_ALGORITHM = "RSA";

	protected byte[] _unsignData;

	protected byte[] _hashOnlyBytes;

	protected byte[] _signerInfoData;

	protected byte[] _signerCert;

	protected byte[] _secondHash;

	protected string _tsaUrl;

	protected string _tsaUsername;

	protected string _tsaPassword;

	protected byte[] _ocsp;

	protected ICollection<byte[]> _clrs;

	protected bool _enableTimestamp;

	protected bool _enableLTV;

	protected bool _addDocumentLvTimestamp;

	protected MessageDigestAlgorithm _hashAlgorithm = MessageDigestAlgorithm.SHA256;

	public BaseHashSigner()
	{
	}

	public BaseHashSigner(byte[] unsignData, byte[] certBytes)
	{
		_unsignData = unsignData;
		_signerCert = certBytes;
	}

	public BaseHashSigner(byte[] unsignData, string certBase64)
	{
		_unsignData = unsignData;
		_signerCert = Convert.FromBase64String(certBase64);
	}

	public BaseHashSigner(byte[] unsignData, string certBase64, string tsaUrl, string tsaUsername, string tsaPassword)
	{
		_unsignData = unsignData;
		_signerCert = Convert.FromBase64String(certBase64);
		_tsaUrl = tsaUrl;
		_tsaUsername = tsaUsername;
		_tsaPassword = tsaPassword;
	}

	public BaseHashSigner(byte[] unsignData, X509Certificate signerCert, string tsaUrl, string tsaUsername, string tsaPassword)
	{
		_unsignData = unsignData;
		_signerCert = signerCert.GetRawCertData();
		_tsaUrl = tsaUrl;
		_tsaUsername = tsaUsername;
		_tsaPassword = tsaPassword;
	}

	public static byte[] FileToByteArray(string fileName)
	{
		byte[] array = null;
		FileStream fileStream = new FileStream(fileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
		BinaryReader binaryReader = new BinaryReader(fileStream);
		try
		{
			long length = new FileInfo(fileName).Length;
			return binaryReader.ReadBytes((int)length);
		}
		finally
		{
			fileStream.Close();
			binaryReader.Close();
		}
	}
}
