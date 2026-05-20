using System;
using System.Security.Cryptography.X509Certificates;
using SignService.Common.HashSignature.Cms;
using SignService.Common.HashSignature.Common;
using SignService.Common.HashSignature.Office;
using SignService.Common.HashSignature.Pdf;
using SignService.Common.HashSignature.Xml;

namespace SignService.Common.HashSignature.Interface;

public class HashSignerFactory
{
	public const string PDF = "PDF";

	public const string OFFICE = "OFFICE";

	public const string XML = "XML";

	public const string CMS = "CMS";

	public static IHashSigner GenerateSigner(byte[] unsignData, string certBase64, string type)
	{
		if (string.IsNullOrEmpty(certBase64))
		{
			throw new FormatException("Bas64 must not be null");
		}
		try
		{
			Convert.FromBase64String(certBase64);
		}
		catch (FormatException ex)
		{
			throw ex;
		}
		return type switch
		{
			"PDF" => new PdfHashSigner(unsignData, certBase64), 
			"OFFICE" => new OfficeHashSigner(unsignData, certBase64), 
			"XML" => new XmlHashSigner(unsignData, certBase64), 
			"CMS" => new CmsHashSigner(unsignData, certBase64), 
			_ => throw new Exception("Unsuported type"), 
		};
	}

	public static IHashSigner GenerateSigner(byte[] unsignData, byte[] certBytes, string type)
	{
		return type switch
		{
			"PDF" => new PdfHashSigner(unsignData, certBytes), 
			"OFFICE" => new OfficeHashSigner(unsignData, certBytes), 
			"XML" => new XmlHashSigner(unsignData, certBytes), 
			"CMS" => new CmsHashSigner(unsignData, certBytes), 
			_ => throw new Exception("Unsuported type"), 
		};
	}

	public static IHashSigner GenerateSigner(byte[] unsignData, string certBase64, string tsaUrl, string tsaUsername, string tsaPassword, string type)
	{
		if (string.IsNullOrEmpty(certBase64))
		{
			throw new FormatException("Bas64 must not be null");
		}
		try
		{
			Convert.FromBase64String(certBase64);
		}
		catch (FormatException ex)
		{
			throw ex;
		}
		return type switch
		{
			"PDF" => new PdfHashSigner(unsignData, certBase64, tsaUrl, tsaUsername, tsaPassword), 
			"OFFICE" => new OfficeHashSigner(unsignData, certBase64), 
			"XML" => new XmlHashSigner(unsignData, certBase64), 
			"CMS" => new CmsHashSigner(unsignData, certBase64), 
			_ => throw new Exception("Unsuported type"), 
		};
	}

	public static IHashSigner GenerateSignerV2(byte[] unsignData, string certBase64, string tsaUrl, string tsaUsername, string tsaPassword, string type)
	{
		if (string.IsNullOrEmpty(certBase64))
		{
			throw new FormatException("Bas64 must not be null");
		}
		try
		{
			Convert.FromBase64String(certBase64);
		}
		catch (FormatException ex)
		{
			throw ex;
		}
		return type switch
		{
			"PDF" => new PdfHashSigner(unsignData, certBase64, tsaUrl, tsaUsername, tsaPassword), 
			"OFFICE" => new OfficeHashSigner(unsignData, certBase64), 
			"XML" => new XmlHashSigner(unsignData, certBase64), 
			"CMS" => new CmsHashSigner(unsignData, certBase64), 
			_ => throw new Exception("Unsuported type"), 
		};
	}

	public static IHashSigner GenerateSigner(string type)
	{
		return type switch
		{
			"PDF" => new PdfHashSigner(), 
			"OFFICE" => new OfficeHashSigner(), 
			"XML" => new XmlHashSigner(), 
			"CMS" => new CmsHashSigner(), 
			_ => throw new Exception("Unsuported type"), 
		};
	}

	public static IHashSigner GenerateSignerV2(string type)
	{
		return type switch
		{
			"PDF" => new PdfHashSigner(), 
			"OFFICE" => new OfficeHashSigner(), 
			"XML" => new XmlHashSigner(), 
			"CMS" => new CmsHashSigner(), 
			_ => throw new Exception("Unsuported type"), 
		};
	}

	public static IHashSigner GenerateSigner(byte[] unsignData, string certBase64, string tsaUrl, string tsaUsername, string tsaPassword, string type, MessageDigestAlgorithm alg)
	{
		if (string.IsNullOrEmpty(certBase64))
		{
			throw new FormatException("Bas64 must not be null");
		}
		try
		{
			Convert.FromBase64String(certBase64);
		}
		catch (FormatException ex)
		{
			throw ex;
		}
		IHashSigner hashSigner = type switch
		{
			"PDF" => new PdfHashSigner(unsignData, certBase64, tsaUrl, tsaUsername, tsaPassword), 
			"OFFICE" => new OfficeHashSigner(unsignData, certBase64), 
			"XML" => new XmlHashSigner(unsignData, certBase64), 
			"CMS" => new CmsHashSigner(unsignData, certBase64), 
			_ => throw new Exception("Unsuported type"), 
		};
		hashSigner.SetHashAlgorithm(alg);
		return hashSigner;
	}

	public static IHashSigner GenerateSigner(byte[] unsignData, X509Certificate x509Cert, string tsaUrl, string tsaUsername, string tsaPassword, string type, MessageDigestAlgorithm alg)
	{
		if (x509Cert == null)
		{
			throw new FormatException("Signer certificate is required");
		}
		switch (type)
		{
		case "PDF":
		{
			IHashSigner hashSigner = new PdfHashSigner(unsignData, x509Cert, tsaUrl, tsaUsername, tsaPassword);
			hashSigner.SetHashAlgorithm(alg);
			return hashSigner;
		}
		default:
			throw new Exception("Unsuported type");
		}
	}
}
