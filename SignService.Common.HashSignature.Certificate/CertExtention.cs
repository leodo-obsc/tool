using System;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509.Store;

namespace SignService.Common.HashSignature.Certificate;

public class CertExtention
{
	protected static Asn1Object GetExtensionValue(X509Certificate2 Cert, string oid)
	{
		try
		{
			if (oid == "")
			{
				throw new ArgumentNullException("oid");
			}
			if (Cert == null)
			{
				throw new ArgumentNullException("Cert");
			}
			return new Asn1InputStream(new X509CertificateParser().ReadCertificate(Cert.GetRawCertData()).GetExtensionValue(new DerObjectIdentifier(oid)).GetOctets() ?? throw new Exception("Cannot get Extention Value")).ReadObject();
		}
		catch (Exception)
		{
		}
		return null;
	}

	protected static Asn1Object GetExtensionValue(Org.BouncyCastle.X509.X509Certificate x509Certificate, string oid)
	{
		try
		{
			if (oid == "")
			{
				throw new ArgumentNullException("oid");
			}
			if (x509Certificate == null)
			{
				throw new ArgumentNullException("Cert");
			}
			return new Asn1InputStream(x509Certificate.GetExtensionValue(new DerObjectIdentifier(oid))?.GetOctets() ?? throw new Exception("Cannot get Extention Value")).ReadObject();
		}
		catch (Exception)
		{
		}
		return null;
	}

	protected static Asn1Object GetExtensionValue(string CertBase64, string oid)
	{
		if (CertBase64 == "")
		{
			throw new ArgumentNullException("CertBase64");
		}
		if (oid == "")
		{
			throw new ArgumentNullException("oid");
		}
		X509Certificate2 x509Certificate = new X509Certificate2(Convert.FromBase64String(CertBase64));
		Org.BouncyCastle.X509.X509Certificate x509Certificate2 = new X509CertificateParser().ReadCertificate(x509Certificate.GetRawCertData());
		if (x509Certificate2 == null)
		{
			return null;
		}
		byte[] octets = x509Certificate2.GetExtensionValue(new DerObjectIdentifier(oid)).GetOctets();
		if (octets == null)
		{
			return null;
		}
		return new Asn1InputStream(octets).ReadObject();
	}

	public static List<string> GetEnhancekeyUsageCert(X509Certificate2 Cert)
	{
		if (Cert == null)
		{
			throw new ArgumentNullException("Cert");
		}
		List<string> list = new List<string>();
		X509ExtensionEnumerator enumerator = Cert.Extensions.GetEnumerator();
		while (enumerator.MoveNext())
		{
			System.Security.Cryptography.X509Certificates.X509Extension current = enumerator.Current;
			if (current.Oid.FriendlyName == "Enhanced Key Usage")
			{
				OidEnumerator enumerator2 = ((X509EnhancedKeyUsageExtension)current).EnhancedKeyUsages.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					Oid current2 = enumerator2.Current;
					list.Add(current2.FriendlyName + "(" + current2.Value + ")");
				}
			}
		}
		return list;
	}

	public static List<string> GetEnhancekeyUsageCert(string CertBase64)
	{
		if (CertBase64 == "")
		{
			throw new ArgumentNullException("CertBase64");
		}
		X509Certificate2 x509Certificate = new X509Certificate2(Convert.FromBase64String(CertBase64));
		List<string> list = new List<string>();
		X509ExtensionEnumerator enumerator = x509Certificate.Extensions.GetEnumerator();
		while (enumerator.MoveNext())
		{
			System.Security.Cryptography.X509Certificates.X509Extension current = enumerator.Current;
			if (current.Oid.FriendlyName == "Enhanced Key Usage")
			{
				OidEnumerator enumerator2 = ((X509EnhancedKeyUsageExtension)current).EnhancedKeyUsages.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					Oid current2 = enumerator2.Current;
					list.Add(current2.FriendlyName + "(" + current2.Value + ")");
				}
			}
		}
		return list;
	}

	public static List<string> GetCRLDistributionPoint(Org.BouncyCastle.X509.X509Certificate Cert)
	{
		if (Cert == null)
		{
			throw new ArgumentNullException("Cert");
		}
		List<string> list = new List<string>();
		Asn1Object extensionValue = GetExtensionValue(Cert, X509Extensions.CrlDistributionPoints.Id);
		if (extensionValue == null)
		{
			return list;
		}
		((Asn1Sequence)extensionValue).GetEnumerator();
		DistributionPoint[] distributionPoints = CrlDistPoint.GetInstance(extensionValue).GetDistributionPoints();
		for (int i = 0; i < distributionPoints.Length; i++)
		{
			string[] array = distributionPoints[i].DistributionPointName.Name.ToString().Split(new char[1] { ' ' });
			list.Add(array[5].Trim());
		}
		return list;
	}

	public static List<string> GetCRLDistributionPoint(X509Certificate2 Cert)
	{
		if (Cert == null)
		{
			throw new ArgumentNullException("Cert");
		}
		List<string> list = new List<string>();
		Asn1Object extensionValue = GetExtensionValue(Cert, X509Extensions.CrlDistributionPoints.Id);
		if (extensionValue == null)
		{
			return list;
		}
		((Asn1Sequence)extensionValue).GetEnumerator();
		DistributionPoint[] distributionPoints = CrlDistPoint.GetInstance(extensionValue).GetDistributionPoints();
		for (int i = 0; i < distributionPoints.Length; i++)
		{
			string[] array = distributionPoints[i].DistributionPointName.Name.ToString().Split(new char[1] { ' ' });
			list.Add(array[5].Trim());
		}
		return list;
	}

	public static List<string> GetCRLDistributionPoint(string CertBase64)
	{
		if (CertBase64 == "")
		{
			throw new ArgumentNullException("CertBase64");
		}
		X509Certificate2 cert = new X509Certificate2(Convert.FromBase64String(CertBase64));
		List<string> list = new List<string>();
		Asn1Object extensionValue = GetExtensionValue(cert, X509Extensions.CrlDistributionPoints.Id);
		if (extensionValue == null)
		{
			return list;
		}
		((Asn1Sequence)extensionValue).GetEnumerator();
		DistributionPoint[] distributionPoints = CrlDistPoint.GetInstance(extensionValue).GetDistributionPoints();
		for (int i = 0; i < distributionPoints.Length; i++)
		{
			string[] array = distributionPoints[i].DistributionPointName.Name.ToString().Split(new char[1] { ' ' });
			list.Add(array[5].Trim());
		}
		return list;
	}

	public static List<string> GetAuthorityInformationAccessOcspUrl(Org.BouncyCastle.X509.X509Certificate Cert)
	{
		if (Cert == null)
		{
			throw new ArgumentNullException("Cert");
		}
		List<string> list = new List<string>();
		try
		{
			Asn1Object extensionValue = GetExtensionValue(Cert, X509Extensions.AuthorityInfoAccess.Id);
			if (extensionValue == null)
			{
				return list;
			}
			IEnumerator enumerator = ((Asn1Sequence)extensionValue).GetEnumerator();
			while (enumerator.MoveNext())
			{
				Asn1Sequence asn1Sequence = (Asn1Sequence)enumerator.Current;
				if (((DerObjectIdentifier)asn1Sequence[0]).Id.Equals("1.3.6.1.5.5.7.48.1"))
				{
					GeneralName instance = GeneralName.GetInstance((Asn1TaggedObject)asn1Sequence[1]);
					list.Add(DerIA5String.GetInstance(instance.Name).GetString());
				}
			}
			return list;
		}
		catch (Exception)
		{
			throw;
		}
	}

	public static List<string> GetAuthorityInformationAccessOcspUrl(X509Certificate2 Cert)
	{
		if (Cert == null)
		{
			throw new ArgumentNullException("Cert");
		}
		List<string> list = new List<string>();
		try
		{
			Asn1Object extensionValue = GetExtensionValue(Cert, X509Extensions.AuthorityInfoAccess.Id);
			if (extensionValue == null)
			{
				return list;
			}
			IEnumerator enumerator = ((Asn1Sequence)extensionValue).GetEnumerator();
			while (enumerator.MoveNext())
			{
				Asn1Sequence asn1Sequence = (Asn1Sequence)enumerator.Current;
				if (((DerObjectIdentifier)asn1Sequence[0]).Id.Equals("1.3.6.1.5.5.7.48.1"))
				{
					GeneralName instance = GeneralName.GetInstance((Asn1TaggedObject)asn1Sequence[1]);
					list.Add(DerIA5String.GetInstance(instance.Name).GetString());
				}
			}
			return list;
		}
		catch (Exception)
		{
			throw;
		}
	}

	public static List<string> GetAuthorityInformationAccessOcspUrl(string CertBase64)
	{
		if (CertBase64 == "")
		{
			throw new ArgumentNullException("CertBase64");
		}
		X509Certificate2 cert = new X509Certificate2(Convert.FromBase64String(CertBase64));
		List<string> list = new List<string>();
		Asn1Object extensionValue = GetExtensionValue(cert, X509Extensions.AuthorityInfoAccess.Id);
		if (extensionValue == null)
		{
			return list;
		}
		IEnumerator enumerator = ((Asn1Sequence)extensionValue).GetEnumerator();
		while (enumerator.MoveNext())
		{
			Asn1Sequence asn1Sequence = (Asn1Sequence)enumerator.Current;
			if (((DerObjectIdentifier)asn1Sequence[0]).Id.Equals("1.3.6.1.5.5.7.48.1"))
			{
				GeneralName instance = GeneralName.GetInstance((Asn1TaggedObject)asn1Sequence[1]);
				list.Add(DerIA5String.GetInstance(instance.Name).GetString());
			}
		}
		return list;
	}

	public static List<string> GetAuthorityInformationAccessIssuerCertUrl(X509Certificate2 Cert)
	{
		if (Cert == null)
		{
			throw new ArgumentNullException("Cert");
		}
		List<string> list = new List<string>();
		Asn1Object extensionValue = GetExtensionValue(Cert, X509Extensions.AuthorityInfoAccess.Id);
		if (extensionValue == null)
		{
			return list;
		}
		IEnumerator enumerator = ((Asn1Sequence)extensionValue).GetEnumerator();
		while (enumerator.MoveNext())
		{
			Asn1Sequence asn1Sequence = (Asn1Sequence)enumerator.Current;
			if (((DerObjectIdentifier)asn1Sequence[0]).Id.Equals("1.3.6.1.5.5.7.48.2"))
			{
				GeneralName instance = GeneralName.GetInstance((Asn1TaggedObject)asn1Sequence[1]);
				list.Add(DerIA5String.GetInstance(instance.Name).GetString());
			}
		}
		return list;
	}

	public static List<string> GetAuthorityInformationAccessIssuerCertUrl(string CertBase64)
	{
		if (CertBase64 == "")
		{
			throw new ArgumentNullException("CertBase64");
		}
		X509Certificate2 cert = new X509Certificate2(Convert.FromBase64String(CertBase64));
		List<string> list = new List<string>();
		Asn1Object extensionValue = GetExtensionValue(cert, X509Extensions.AuthorityInfoAccess.Id);
		if (extensionValue == null)
		{
			return list;
		}
		IEnumerator enumerator = ((Asn1Sequence)extensionValue).GetEnumerator();
		while (enumerator.MoveNext())
		{
			Asn1Sequence asn1Sequence = (Asn1Sequence)enumerator.Current;
			if (((DerObjectIdentifier)asn1Sequence[0]).Id.Equals("1.3.6.1.5.5.7.48.2"))
			{
				GeneralName instance = GeneralName.GetInstance((Asn1TaggedObject)asn1Sequence[1]);
				list.Add(DerIA5String.GetInstance(instance.Name).GetString());
			}
		}
		return list;
	}

	public static bool IsSelfSigned(Org.BouncyCastle.X509.X509Certificate certificate)
	{
		if (certificate == null)
		{
			throw new ArgumentNullException("certificate");
		}
		try
		{
			certificate.Verify(certificate.GetPublicKey());
			return true;
		}
		catch (InvalidKeyException)
		{
			return false;
		}
	}

	public static string GetSubjectKeyIdentifier(X509Certificate2 cert)
	{
		byte[] array = null;
		string result = null;
		Org.BouncyCastle.X509.X509Certificate x509Certificate = new X509CertificateParser().ReadCertificate(cert.GetRawCertData());
		try
		{
			array = new SubjectKeyIdentifierStructure(x509Certificate.GetExtensionValue(new DerObjectIdentifier(X509Extensions.SubjectKeyIdentifier.Id))).GetKeyIdentifier();
			if (array != null)
			{
				result = Encoding.ASCII.GetString(Hex.Encode(array));
			}
		}
		catch (Exception)
		{
			return null;
		}
		return result;
	}

	public static string GetAuthorityKeyIdentifier(X509Certificate2 cert)
	{
		byte[] array = null;
		string result = null;
		Org.BouncyCastle.X509.X509Certificate x509Certificate = new X509CertificateParser().ReadCertificate(cert.GetRawCertData());
		try
		{
			array = new AuthorityKeyIdentifierStructure(x509Certificate.GetExtensionValue(new DerObjectIdentifier(X509Extensions.AuthorityKeyIdentifier.Id))).GetKeyIdentifier();
			if (array != null)
			{
				result = Encoding.ASCII.GetString(Hex.Encode(array));
			}
		}
		catch (Exception)
		{
			return null;
		}
		return result;
	}

	public static ICollection<Org.BouncyCastle.X509.X509Certificate> BuildCertPath(Org.BouncyCastle.X509.X509Certificate signingCert, List<Org.BouncyCastle.X509.X509Certificate> otherCerts)
	{
		List<Org.BouncyCastle.X509.X509Certificate> list = new List<Org.BouncyCastle.X509.X509Certificate>();
		ISet set = new HashSet();
		if (IsSelfSigned(signingCert))
		{
			list.Add(signingCert);
		}
		else
		{
			otherCerts.Add(signingCert);
			if (otherCerts != null)
			{
				foreach (Org.BouncyCastle.X509.X509Certificate otherCert in otherCerts)
				{
					otherCerts.Add(otherCert);
					if (IsSelfSigned(otherCert))
					{
						set.Add(new TrustAnchor(otherCert, null));
					}
				}
			}
			if (set.Count < 1)
			{
				throw new PkixCertPathBuilderException("Provided certificates do not contain self-signed root certificate");
			}
			X509CertStoreSelector x509CertStoreSelector = new X509CertStoreSelector();
			x509CertStoreSelector.Certificate = signingCert;
			PkixBuilderParameters pkixBuilderParameters = new PkixBuilderParameters(set, x509CertStoreSelector);
			pkixBuilderParameters.AddStore(X509StoreFactory.Create("Certificate/Collection", new X509CollectionStoreParameters(otherCerts)));
			pkixBuilderParameters.IsRevocationEnabled = false;
			PkixCertPathBuilderResult pkixCertPathBuilderResult = new PkixCertPathBuilder().Build(pkixBuilderParameters);
			foreach (Org.BouncyCastle.X509.X509Certificate certificate in pkixCertPathBuilderResult.CertPath.Certificates)
			{
				list.Add(certificate);
			}
			list.Add(pkixCertPathBuilderResult.TrustAnchor.TrustedCert);
		}
		return list;
	}

	public static bool isHasAnyPurpose(X509Certificate2 Cert)
	{
		if (Cert == null)
		{
			throw new ArgumentNullException("Cert");
		}
		List<string> list = new List<string>();
		X509ExtensionEnumerator enumerator = Cert.Extensions.GetEnumerator();
		while (enumerator.MoveNext())
		{
			System.Security.Cryptography.X509Certificates.X509Extension current = enumerator.Current;
			if (current.Oid.FriendlyName == "Enhanced Key Usage")
			{
				OidEnumerator enumerator2 = ((X509EnhancedKeyUsageExtension)current).EnhancedKeyUsages.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					Oid current2 = enumerator2.Current;
					list.Add(current2.Value);
				}
			}
		}
		return list.Contains("2.5.29.37.0");
	}

	public static bool isHasServerAuthentication(X509Certificate2 Cert)
	{
		if (Cert == null)
		{
			throw new ArgumentNullException("Cert");
		}
		List<string> list = new List<string>();
		X509ExtensionEnumerator enumerator = Cert.Extensions.GetEnumerator();
		while (enumerator.MoveNext())
		{
			System.Security.Cryptography.X509Certificates.X509Extension current = enumerator.Current;
			if (current.Oid.FriendlyName == "Enhanced Key Usage")
			{
				OidEnumerator enumerator2 = ((X509EnhancedKeyUsageExtension)current).EnhancedKeyUsages.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					Oid current2 = enumerator2.Current;
					list.Add(current2.Value);
				}
			}
		}
		return list.Contains("1.3.6.1.5.5.7.3.1");
	}

	public static bool isHasClientAuthentication(X509Certificate2 Cert)
	{
		if (Cert == null)
		{
			throw new ArgumentNullException("Cert");
		}
		List<string> list = new List<string>();
		X509ExtensionEnumerator enumerator = Cert.Extensions.GetEnumerator();
		while (enumerator.MoveNext())
		{
			System.Security.Cryptography.X509Certificates.X509Extension current = enumerator.Current;
			if (current.Oid.FriendlyName == "Enhanced Key Usage")
			{
				OidEnumerator enumerator2 = ((X509EnhancedKeyUsageExtension)current).EnhancedKeyUsages.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					Oid current2 = enumerator2.Current;
					list.Add(current2.Value);
				}
			}
		}
		return list.Contains("1.3.6.1.5.5.7.3.2");
	}

	public static bool isHasCodeSigning(X509Certificate2 Cert)
	{
		if (Cert == null)
		{
			throw new ArgumentNullException("Cert");
		}
		List<string> list = new List<string>();
		X509ExtensionEnumerator enumerator = Cert.Extensions.GetEnumerator();
		while (enumerator.MoveNext())
		{
			System.Security.Cryptography.X509Certificates.X509Extension current = enumerator.Current;
			if (current.Oid.FriendlyName == "Enhanced Key Usage")
			{
				OidEnumerator enumerator2 = ((X509EnhancedKeyUsageExtension)current).EnhancedKeyUsages.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					Oid current2 = enumerator2.Current;
					list.Add(current2.Value);
				}
			}
		}
		return list.Contains("1.3.6.1.5.5.7.3.3");
	}

	public static bool isHasSecureEmail(X509Certificate2 Cert)
	{
		if (Cert == null)
		{
			throw new ArgumentNullException("Cert");
		}
		List<string> list = new List<string>();
		X509ExtensionEnumerator enumerator = Cert.Extensions.GetEnumerator();
		while (enumerator.MoveNext())
		{
			System.Security.Cryptography.X509Certificates.X509Extension current = enumerator.Current;
			if (current.Oid.FriendlyName == "Enhanced Key Usage")
			{
				OidEnumerator enumerator2 = ((X509EnhancedKeyUsageExtension)current).EnhancedKeyUsages.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					Oid current2 = enumerator2.Current;
					list.Add(current2.Value);
				}
			}
		}
		return list.Contains("1.3.6.1.5.5.7.3.4");
	}

	public static bool isHasTimeStamping(X509Certificate2 Cert)
	{
		if (Cert == null)
		{
			throw new ArgumentNullException("Cert");
		}
		List<string> list = new List<string>();
		X509ExtensionEnumerator enumerator = Cert.Extensions.GetEnumerator();
		while (enumerator.MoveNext())
		{
			System.Security.Cryptography.X509Certificates.X509Extension current = enumerator.Current;
			if (current.Oid.FriendlyName == "Enhanced Key Usage")
			{
				OidEnumerator enumerator2 = ((X509EnhancedKeyUsageExtension)current).EnhancedKeyUsages.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					Oid current2 = enumerator2.Current;
					list.Add(current2.Value);
				}
			}
		}
		return list.Contains("1.3.6.1.5.5.7.3.8");
	}

	public static bool isHasOCSPSigning(X509Certificate2 Cert)
	{
		if (Cert == null)
		{
			throw new ArgumentNullException("Cert");
		}
		List<string> list = new List<string>();
		X509ExtensionEnumerator enumerator = Cert.Extensions.GetEnumerator();
		while (enumerator.MoveNext())
		{
			System.Security.Cryptography.X509Certificates.X509Extension current = enumerator.Current;
			if (current.Oid.FriendlyName == "Enhanced Key Usage")
			{
				OidEnumerator enumerator2 = ((X509EnhancedKeyUsageExtension)current).EnhancedKeyUsages.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					Oid current2 = enumerator2.Current;
					list.Add(current2.Value);
				}
			}
		}
		return list.Contains("1.3.6.1.5.5.7.3.9");
	}

	public static bool isHasCTUsageSinging(X509Certificate2 Cert)
	{
		if (Cert == null)
		{
			throw new ArgumentNullException("Cert");
		}
		List<string> list = new List<string>();
		X509ExtensionEnumerator enumerator = Cert.Extensions.GetEnumerator();
		while (enumerator.MoveNext())
		{
			System.Security.Cryptography.X509Certificates.X509Extension current = enumerator.Current;
			if (current.Oid.FriendlyName == "Enhanced Key Usage")
			{
				OidEnumerator enumerator2 = ((X509EnhancedKeyUsageExtension)current).EnhancedKeyUsages.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					Oid current2 = enumerator2.Current;
					list.Add(current2.Value);
				}
			}
		}
		return list.Contains("1.3.6.1.4.1.311.10.3.1");
	}

	public static bool isHasSmartCardLogon(X509Certificate2 Cert)
	{
		if (Cert == null)
		{
			throw new ArgumentNullException("Cert");
		}
		List<string> list = new List<string>();
		X509ExtensionEnumerator enumerator = Cert.Extensions.GetEnumerator();
		while (enumerator.MoveNext())
		{
			System.Security.Cryptography.X509Certificates.X509Extension current = enumerator.Current;
			if (current.Oid.FriendlyName == "Enhanced Key Usage")
			{
				OidEnumerator enumerator2 = ((X509EnhancedKeyUsageExtension)current).EnhancedKeyUsages.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					Oid current2 = enumerator2.Current;
					list.Add(current2.Value);
				}
			}
		}
		return list.Contains("1.3.6.1.4.1.311.20.2.2");
	}

	public static bool isHasDocumentSigning(X509Certificate2 Cert)
	{
		if (Cert == null)
		{
			throw new ArgumentNullException("Cert");
		}
		List<string> list = new List<string>();
		X509ExtensionEnumerator enumerator = Cert.Extensions.GetEnumerator();
		while (enumerator.MoveNext())
		{
			System.Security.Cryptography.X509Certificates.X509Extension current = enumerator.Current;
			if (current.Oid.FriendlyName == "Enhanced Key Usage")
			{
				OidEnumerator enumerator2 = ((X509EnhancedKeyUsageExtension)current).EnhancedKeyUsages.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					Oid current2 = enumerator2.Current;
					list.Add(current2.Value);
				}
			}
		}
		return list.Contains("1.3.6.1.4.1.311.10.3.12");
	}

	public static bool isHasEncryptingFileSystem(X509Certificate2 Cert)
	{
		if (Cert == null)
		{
			throw new ArgumentNullException("Cert");
		}
		List<string> list = new List<string>();
		X509ExtensionEnumerator enumerator = Cert.Extensions.GetEnumerator();
		while (enumerator.MoveNext())
		{
			System.Security.Cryptography.X509Certificates.X509Extension current = enumerator.Current;
			if (current.Oid.FriendlyName == "Enhanced Key Usage")
			{
				OidEnumerator enumerator2 = ((X509EnhancedKeyUsageExtension)current).EnhancedKeyUsages.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					Oid current2 = enumerator2.Current;
					list.Add(current2.Value);
				}
			}
		}
		return list.Contains("1.3.6.1.4.1.311.10.3.4");
	}

	public static bool isHasFileRecovery(X509Certificate2 Cert)
	{
		if (Cert == null)
		{
			throw new ArgumentNullException("Cert");
		}
		List<string> list = new List<string>();
		X509ExtensionEnumerator enumerator = Cert.Extensions.GetEnumerator();
		while (enumerator.MoveNext())
		{
			System.Security.Cryptography.X509Certificates.X509Extension current = enumerator.Current;
			if (current.Oid.FriendlyName == "Enhanced Key Usage")
			{
				OidEnumerator enumerator2 = ((X509EnhancedKeyUsageExtension)current).EnhancedKeyUsages.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					Oid current2 = enumerator2.Current;
					list.Add(current2.Value);
				}
			}
		}
		return list.Contains("1.3.6.1.4.1.311.10.3.4.1");
	}

	public static bool isHasAnyPurpose(string CertBase64)
	{
		if (CertBase64 == "")
		{
			throw new ArgumentNullException("CertBase64");
		}
		X509Certificate2 x509Certificate = new X509Certificate2(Convert.FromBase64String(CertBase64));
		List<string> list = new List<string>();
		X509ExtensionEnumerator enumerator = x509Certificate.Extensions.GetEnumerator();
		while (enumerator.MoveNext())
		{
			System.Security.Cryptography.X509Certificates.X509Extension current = enumerator.Current;
			if (current.Oid.FriendlyName == "Enhanced Key Usage")
			{
				OidEnumerator enumerator2 = ((X509EnhancedKeyUsageExtension)current).EnhancedKeyUsages.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					Oid current2 = enumerator2.Current;
					list.Add(current2.Value);
				}
			}
		}
		return list.Contains("2.5.29.37.0");
	}

	public static bool isHasServerAuthentication(string CertBase64)
	{
		if (CertBase64 == "")
		{
			throw new ArgumentNullException("CertBase64");
		}
		X509Certificate2 x509Certificate = new X509Certificate2(Convert.FromBase64String(CertBase64));
		List<string> list = new List<string>();
		X509ExtensionEnumerator enumerator = x509Certificate.Extensions.GetEnumerator();
		while (enumerator.MoveNext())
		{
			System.Security.Cryptography.X509Certificates.X509Extension current = enumerator.Current;
			if (current.Oid.FriendlyName == "Enhanced Key Usage")
			{
				OidEnumerator enumerator2 = ((X509EnhancedKeyUsageExtension)current).EnhancedKeyUsages.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					Oid current2 = enumerator2.Current;
					list.Add(current2.Value);
				}
			}
		}
		return list.Contains("1.3.6.1.5.5.7.3.1");
	}

	public static bool isHasClientAuthentication(string CertBase64)
	{
		if (CertBase64 == "")
		{
			throw new ArgumentNullException("CertBase64");
		}
		X509Certificate2 x509Certificate = new X509Certificate2(Convert.FromBase64String(CertBase64));
		List<string> list = new List<string>();
		X509ExtensionEnumerator enumerator = x509Certificate.Extensions.GetEnumerator();
		while (enumerator.MoveNext())
		{
			System.Security.Cryptography.X509Certificates.X509Extension current = enumerator.Current;
			if (current.Oid.FriendlyName == "Enhanced Key Usage")
			{
				OidEnumerator enumerator2 = ((X509EnhancedKeyUsageExtension)current).EnhancedKeyUsages.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					Oid current2 = enumerator2.Current;
					list.Add(current2.Value);
				}
			}
		}
		return list.Contains("1.3.6.1.5.5.7.3.2");
	}

	public static bool isHasCodeSigning(string CertBase64)
	{
		if (CertBase64 == "")
		{
			throw new ArgumentNullException("CertBase64");
		}
		X509Certificate2 x509Certificate = new X509Certificate2(Convert.FromBase64String(CertBase64));
		List<string> list = new List<string>();
		X509ExtensionEnumerator enumerator = x509Certificate.Extensions.GetEnumerator();
		while (enumerator.MoveNext())
		{
			System.Security.Cryptography.X509Certificates.X509Extension current = enumerator.Current;
			if (current.Oid.FriendlyName == "Enhanced Key Usage")
			{
				OidEnumerator enumerator2 = ((X509EnhancedKeyUsageExtension)current).EnhancedKeyUsages.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					Oid current2 = enumerator2.Current;
					list.Add(current2.Value);
				}
			}
		}
		return list.Contains("1.3.6.1.5.5.7.3.3");
	}

	public static bool isHasSecureEmail(string CertBase64)
	{
		if (CertBase64 == "")
		{
			throw new ArgumentNullException("CertBase64");
		}
		X509Certificate2 x509Certificate = new X509Certificate2(Convert.FromBase64String(CertBase64));
		List<string> list = new List<string>();
		X509ExtensionEnumerator enumerator = x509Certificate.Extensions.GetEnumerator();
		while (enumerator.MoveNext())
		{
			System.Security.Cryptography.X509Certificates.X509Extension current = enumerator.Current;
			if (current.Oid.FriendlyName == "Enhanced Key Usage")
			{
				OidEnumerator enumerator2 = ((X509EnhancedKeyUsageExtension)current).EnhancedKeyUsages.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					Oid current2 = enumerator2.Current;
					list.Add(current2.Value);
				}
			}
		}
		return list.Contains("1.3.6.1.5.5.7.3.4");
	}

	public static bool isHasTimeStamping(string CertBase64)
	{
		if (CertBase64 == "")
		{
			throw new ArgumentNullException("CertBase64");
		}
		X509Certificate2 x509Certificate = new X509Certificate2(Convert.FromBase64String(CertBase64));
		List<string> list = new List<string>();
		X509ExtensionEnumerator enumerator = x509Certificate.Extensions.GetEnumerator();
		while (enumerator.MoveNext())
		{
			System.Security.Cryptography.X509Certificates.X509Extension current = enumerator.Current;
			if (current.Oid.FriendlyName == "Enhanced Key Usage")
			{
				OidEnumerator enumerator2 = ((X509EnhancedKeyUsageExtension)current).EnhancedKeyUsages.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					Oid current2 = enumerator2.Current;
					list.Add(current2.Value);
				}
			}
		}
		return list.Contains("1.3.6.1.5.5.7.3.8");
	}

	public static bool isHasOCSPSigning(string CertBase64)
	{
		if (CertBase64 == "")
		{
			throw new ArgumentNullException("CertBase64");
		}
		X509Certificate2 x509Certificate = new X509Certificate2(Convert.FromBase64String(CertBase64));
		List<string> list = new List<string>();
		X509ExtensionEnumerator enumerator = x509Certificate.Extensions.GetEnumerator();
		while (enumerator.MoveNext())
		{
			System.Security.Cryptography.X509Certificates.X509Extension current = enumerator.Current;
			if (current.Oid.FriendlyName == "Enhanced Key Usage")
			{
				OidEnumerator enumerator2 = ((X509EnhancedKeyUsageExtension)current).EnhancedKeyUsages.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					Oid current2 = enumerator2.Current;
					list.Add(current2.Value);
				}
			}
		}
		return list.Contains("1.3.6.1.5.5.7.3.9");
	}

	public static bool isHasCTUsageSinging(string CertBase64)
	{
		if (CertBase64 == "")
		{
			throw new ArgumentNullException("CertBase64");
		}
		X509Certificate2 x509Certificate = new X509Certificate2(Convert.FromBase64String(CertBase64));
		List<string> list = new List<string>();
		X509ExtensionEnumerator enumerator = x509Certificate.Extensions.GetEnumerator();
		while (enumerator.MoveNext())
		{
			System.Security.Cryptography.X509Certificates.X509Extension current = enumerator.Current;
			if (current.Oid.FriendlyName == "Enhanced Key Usage")
			{
				OidEnumerator enumerator2 = ((X509EnhancedKeyUsageExtension)current).EnhancedKeyUsages.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					Oid current2 = enumerator2.Current;
					list.Add(current2.Value);
				}
			}
		}
		return list.Contains("1.3.6.1.4.1.311.10.3.1");
	}

	public static bool isHasSmartCardLogon(string CertBase64)
	{
		if (CertBase64 == "")
		{
			throw new ArgumentNullException("CertBase64");
		}
		X509Certificate2 x509Certificate = new X509Certificate2(Convert.FromBase64String(CertBase64));
		List<string> list = new List<string>();
		X509ExtensionEnumerator enumerator = x509Certificate.Extensions.GetEnumerator();
		while (enumerator.MoveNext())
		{
			System.Security.Cryptography.X509Certificates.X509Extension current = enumerator.Current;
			if (current.Oid.FriendlyName == "Enhanced Key Usage")
			{
				OidEnumerator enumerator2 = ((X509EnhancedKeyUsageExtension)current).EnhancedKeyUsages.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					Oid current2 = enumerator2.Current;
					list.Add(current2.Value);
				}
			}
		}
		return list.Contains("1.3.6.1.4.1.311.20.2.2");
	}

	public static bool isHasDocumentSigning(string CertBase64)
	{
		if (CertBase64 == "")
		{
			throw new ArgumentNullException("CertBase64");
		}
		return isHasDocumentSigning(new X509Certificate2(Convert.FromBase64String(CertBase64)));
	}

	public static bool isHasEncryptingFileSystem(string CertBase64)
	{
		if (CertBase64 == "")
		{
			throw new ArgumentNullException("CertBase64");
		}
		X509Certificate2 x509Certificate = new X509Certificate2(Convert.FromBase64String(CertBase64));
		List<string> list = new List<string>();
		X509ExtensionEnumerator enumerator = x509Certificate.Extensions.GetEnumerator();
		while (enumerator.MoveNext())
		{
			System.Security.Cryptography.X509Certificates.X509Extension current = enumerator.Current;
			if (current.Oid.FriendlyName == "Enhanced Key Usage")
			{
				OidEnumerator enumerator2 = ((X509EnhancedKeyUsageExtension)current).EnhancedKeyUsages.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					Oid current2 = enumerator2.Current;
					list.Add(current2.Value);
				}
			}
		}
		return list.Contains("1.3.6.1.4.1.311.10.3.4");
	}

	public static bool isHasFileRecovery(string CertBase64)
	{
		if (CertBase64 == "")
		{
			throw new ArgumentNullException("CertBase64");
		}
		X509Certificate2 x509Certificate = new X509Certificate2(Convert.FromBase64String(CertBase64));
		List<string> list = new List<string>();
		X509ExtensionEnumerator enumerator = x509Certificate.Extensions.GetEnumerator();
		while (enumerator.MoveNext())
		{
			System.Security.Cryptography.X509Certificates.X509Extension current = enumerator.Current;
			if (current.Oid.FriendlyName == "Enhanced Key Usage")
			{
				OidEnumerator enumerator2 = ((X509EnhancedKeyUsageExtension)current).EnhancedKeyUsages.GetEnumerator();
				while (enumerator2.MoveNext())
				{
					Oid current2 = enumerator2.Current;
					list.Add(current2.Value);
				}
			}
		}
		return list.Contains("1.3.6.1.4.1.311.10.3.4.1");
	}
}
