using System;
using SignService.Common.HashSignature.Cms;
using SignService.Common.HashSignature.Common;
using SignService.Common.HashSignature.Office;
using SignService.Common.HashSignature.Xml;

namespace SignService.Common.HashSignature.Interface
{
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
			switch (type)
			{
			case "OFFICE":
				return new OfficeHashSigner(unsignData, certBase64);
			case "XML":
				return new XmlHashSigner(unsignData, certBase64);
			case "CMS":
				return new CmsHashSigner(unsignData, certBase64);
			default:
				throw new Exception("Unsuported type");
			}
		}

		public static IHashSigner GenerateSigner(byte[] unsignData, byte[] certBytes, string type)
		{
			switch (type)
			{
			case "OFFICE":
				return new OfficeHashSigner(unsignData, certBytes);
			case "XML":
				return new XmlHashSigner(unsignData, certBytes);
			case "CMS":
				return new CmsHashSigner(unsignData, certBytes);
			default:
				throw new Exception("Unsuported type");
			}
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
			switch (type)
			{
			case "OFFICE":
				return new OfficeHashSigner(unsignData, certBase64);
			case "XML":
				return new XmlHashSigner(unsignData, certBase64);
			case "CMS":
				return new CmsHashSigner(unsignData, certBase64);
			default:
				throw new Exception("Unsuported type");
			}
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
			switch (type)
			{
			case "OFFICE":
				return new OfficeHashSigner(unsignData, certBase64);
			case "XML":
				return new XmlHashSigner(unsignData, certBase64);
			case "CMS":
				return new CmsHashSigner(unsignData, certBase64);
			default:
				throw new Exception("Unsuported type");
			}
		}

		public static IHashSigner GenerateSigner(string type)
		{
			switch (type)
			{
			case "OFFICE":
				return new OfficeHashSigner();
			case "XML":
				return new XmlHashSigner();
			case "CMS":
				return new CmsHashSigner();
			default:
				throw new Exception("Unsuported type");
			}
		}

		public static IHashSigner GenerateSignerV2(string type)
		{
			switch (type)
			{
			case "OFFICE":
				return new OfficeHashSigner();
			case "XML":
				return new XmlHashSigner();
			case "CMS":
				return new CmsHashSigner();
			default:
				throw new Exception("Unsuported type");
			}
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
			IHashSigner hashSigner;
			switch (type)
			{
			case "OFFICE":
				hashSigner = new OfficeHashSigner(unsignData, certBase64);
				break;
			case "XML":
				hashSigner = new XmlHashSigner(unsignData, certBase64);
				break;
			case "CMS":
				hashSigner = new CmsHashSigner(unsignData, certBase64);
				break;
			default:
				throw new Exception("Unsuported type");
			}
			hashSigner.SetHashAlgorithm(alg);
			return hashSigner;
		}
	}
}
