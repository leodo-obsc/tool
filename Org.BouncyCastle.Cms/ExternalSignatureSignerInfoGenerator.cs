using System;
using System.Collections;
using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms;

public class ExternalSignatureSignerInfoGenerator
{
	public byte[] signedBytes;

	private static readonly Org.BouncyCastle.Cms.CmsSignedHelper Helper = Org.BouncyCastle.Cms.CmsSignedHelper.Instance;

	public string digestOID { get; set; }

	public string encOID { get; set; }

	public X509Certificate cert { get; set; }

	public Asn1Set signedAttr { get; set; }

	public Asn1Set unsignedAttr { get; set; }

	public ExternalSignatureSignerInfoGenerator(string digestOID, string encOID)
	{
		this.digestOID = digestOID;
		this.encOID = encOID;
	}

	private string getDigestAlgName()
	{
		if (CmsSignedGenerator.DigestMD5.Equals(digestOID))
		{
			return "MD5";
		}
		if (CmsSignedGenerator.DigestSha1.Equals(digestOID))
		{
			return "SHA1";
		}
		if (!CmsSignedGenerator.DigestSha256.Equals(digestOID))
		{
			return digestOID;
		}
		return "SHA256";
	}

	private string getEncryptionAlgName()
	{
		if (CmsSignedGenerator.EncryptionDsa.Equals(encOID))
		{
			return "DSA";
		}
		if (!CmsSignedGenerator.EncryptionRsa.Equals(encOID))
		{
			return encOID;
		}
		return "RSA";
	}

	public SignerInfo Generate()
	{
		AlgorithmIdentifier digAlgorithm = new AlgorithmIdentifier(new DerObjectIdentifier(digestOID), DerNull.Instance);
		AlgorithmIdentifier digEncryptionAlgorithm = ((!encOID.Equals(CmsSignedGenerator.EncryptionDsa)) ? new AlgorithmIdentifier(new DerObjectIdentifier(encOID), DerNull.Instance) : new AlgorithmIdentifier(new DerObjectIdentifier(encOID)));
		Asn1OctetString encryptedDigest = new DerOctetString(signedBytes);
		return new SignerInfo(new SignerIdentifier(new IssuerAndSerialNumber(TbsCertificateStructure.GetInstance(new Asn1InputStream(cert.GetTbsCertificate()).ReadObject()).Issuer, cert.SerialNumber)), digAlgorithm, signedAttr, digEncryptionAlgorithm, encryptedDigest, unsignedAttr);
	}

	private byte[] _doDigest(CmsProcessable content, string sigProvider)
	{
		IDigest digestInstance = Helper.GetDigestInstance(getDigestAlgName());
		content?.Write(new DigOutputStream(digestInstance));
		return DigestUtilities.DoFinal(digestInstance);
	}

	public byte[] GetBytesToSign(Asn1Encodable contentType, CmsProcessable msg, DateTime signingDate, string sigProvider)
	{
		byte[] str = _doDigest(msg, "BC");
		if (signedAttr != null)
		{
			new Asn1EncodableVector(new Asn1Encodable[0]);
		}
		else
		{
			signedAttr = new DerSet(new Asn1EncodableVector(new Asn1Encodable[0])
			{
				new Asn1Encodable[1]
				{
					new Org.BouncyCastle.Asn1.Cms.Attribute(CmsAttributes.ContentType, new DerSet(contentType))
				},
				new Asn1Encodable[1]
				{
					new Org.BouncyCastle.Asn1.Cms.Attribute(CmsAttributes.SigningTime, new DerSet(new DerUtcTime(signingDate)))
				},
				new Asn1Encodable[1]
				{
					new Org.BouncyCastle.Asn1.Cms.Attribute(CmsAttributes.MessageDigest, new DerSet(new DerOctetString(str)))
				}
			});
		}
		Asn1Set asn1Set = unsignedAttr;
		if (asn1Set != null)
		{
			Asn1EncodableVector asn1EncodableVector = new Asn1EncodableVector(new Asn1Encodable[0]);
			IEnumerator enumerator = asn1Set.GetEnumerator();
			if (enumerator.MoveNext())
			{
				asn1EncodableVector.Add(Org.BouncyCastle.Asn1.Cms.Attribute.GetInstance(enumerator.Current));
			}
			unsignedAttr = new DerSet(asn1EncodableVector);
		}
		byte[] array = null;
		using MemoryStream memoryStream = new MemoryStream();
		DerOutputStream derOutputStream = new DerOutputStream(memoryStream);
		derOutputStream.WriteObject(signedAttr);
		array = memoryStream.ToArray();
		derOutputStream.Close();
		memoryStream.Close();
		return array;
	}
}
