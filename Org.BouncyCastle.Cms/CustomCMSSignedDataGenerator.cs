using System.Collections;
using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
    public class CustomCMSSignedDataGenerator : CmsSignedGenerator
    {
    	private class SignerInf
    	{
    		private readonly CmsSignedGenerator outer;

    		private readonly AsymmetricKeyParameter key;

    		private readonly SignerIdentifier signerIdentifier;

    		private readonly string digestOID;

    		private readonly string encOID;

    		private readonly CmsAttributeTableGenerator sAttr;

    		private readonly CmsAttributeTableGenerator unsAttr;

    		private readonly Org.BouncyCastle.Asn1.Cms.AttributeTable baseSignedTable;

    		internal AlgorithmIdentifier DigestAlgorithmID => new AlgorithmIdentifier(new DerObjectIdentifier(digestOID), DerNull.Instance);

    		internal CmsAttributeTableGenerator SignedAttributes => sAttr;

    		internal CmsAttributeTableGenerator UnsignedAttributes => unsAttr;

    		internal SignerInf(CmsSignedGenerator outer, AsymmetricKeyParameter key, SignerIdentifier signerIdentifier, string digestOID, string encOID, CmsAttributeTableGenerator sAttr, CmsAttributeTableGenerator unsAttr, Org.BouncyCastle.Asn1.Cms.AttributeTable baseSignedTable)
    		{
    			this.outer = outer;
    			this.key = key;
    			this.signerIdentifier = signerIdentifier;
    			this.digestOID = digestOID;
    			this.encOID = encOID;
    			this.sAttr = sAttr;
    			this.unsAttr = unsAttr;
    			this.baseSignedTable = baseSignedTable;
    		}

    		internal SignerInfo ToSignerInfo(DerObjectIdentifier contentType, CmsProcessable content, SecureRandom random)
    		{
    			AlgorithmIdentifier digestAlgorithmID = DigestAlgorithmID;
    			string digestAlgName = Helper.GetDigestAlgName(digestOID);
    			IDigest digestInstance = Helper.GetDigestInstance(digestAlgName);
    			string algorithm = digestAlgName + "with" + Helper.GetEncryptionAlgName(encOID);
    			ISigner obj = ((outer._signerProvider != null) ? outer._signerProvider : Helper.GetSignatureInstance(algorithm));
    			byte[] array = null;
    			byte[] preCalculatedDigest = ((CustomCMSSignedDataGenerator)outer).PreCalculatedDigest;
    			if (preCalculatedDigest != null)
    			{
    				array = preCalculatedDigest;
    			}
    			else if (content != null)
    			{
    				content.Write(new DigOutputStream(digestInstance));
    				array = DigestUtilities.DoFinal(digestInstance);
    			}
    			outer._digests.Add(digestOID, array.Clone());
    			obj.Init(forSigning: true, new ParametersWithRandom(key, random));
    			Stream stream = new BufferedStream(new SigOutputStream(obj));
    			Asn1Set asn1Set = null;
    			if (sAttr != null)
    			{
    				Org.BouncyCastle.Asn1.Cms.AttributeTable attributeTable = sAttr.GetAttributes(outer.GetBaseParameters(contentType, digestAlgorithmID, array));
    				if (contentType == null && attributeTable != null && attributeTable[CmsAttributes.ContentType] != null)
    				{
    					IDictionary dictionary = attributeTable.ToDictionary();
    					dictionary.Remove(CmsAttributes.ContentType);
    					attributeTable = new Org.BouncyCastle.Asn1.Cms.AttributeTable(dictionary);
    				}
    				asn1Set = outer.GetAttributeSet(attributeTable);
    				new DerOutputStream(stream).WriteObject(asn1Set);
    			}
    			else
    			{
    				content?.Write(stream);
    			}
    			stream.Close();
    			byte[] array2 = obj.GenerateSignature();
    			Asn1Set unauthenticatedAttributes = null;
    			if (unsAttr != null)
    			{
    				IDictionary baseParameters = outer.GetBaseParameters(contentType, digestAlgorithmID, array);
    				baseParameters[CmsAttributeTableParameter.Signature] = array2.Clone();
    				unauthenticatedAttributes = outer.GetAttributeSet(unsAttr.GetAttributes(baseParameters));
    			}
    			AlgorithmIdentifier encAlgorithmIdentifier = CmsSignedGenerator.GetEncAlgorithmIdentifier(new DerObjectIdentifier(encOID), SignerUtilities.GetDefaultX509Parameters(algorithm));
    			return new SignerInfo(signerIdentifier, digestAlgorithmID, asn1Set, encAlgorithmIdentifier, new DerOctetString(array2), unauthenticatedAttributes);
    		}
    	}

    	private static readonly Org.BouncyCastle.Cms.CmsSignedHelper Helper = Org.BouncyCastle.Cms.CmsSignedHelper.Instance;

    	private readonly IList signerInfs = Org.BouncyCastle.Utilities.Platform.CreateArrayList();

    	public ISigner SignerProvider
    	{
    		get
    		{
    			return _signerProvider;
    		}
    		set
    		{
    			_signerProvider = value;
    		}
    	}

    	public byte[] PreCalculatedDigest { get; set; }

    	public CustomCMSSignedDataGenerator()
    	{
    	}

    	public CustomCMSSignedDataGenerator(SecureRandom rand)
    		: base(rand)
    	{
    	}

    	public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string digestOID)
    	{
    		AddSigner(privateKey, cert, GetEncOid(privateKey, digestOID), digestOID);
    	}

    	public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string encryptionOID, string digestOID)
    	{
    		doAddSigner(privateKey, CmsSignedGenerator.GetSignerIdentifier(cert), encryptionOID, digestOID, new DefaultSignedAttributeTableGenerator(), null, null);
    	}

    	public void AddSigner(ExternalSignatureSignerInfoGenerator si)
    	{
    		signerInfs.Add(si);
    	}

    	public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string digestOID)
    	{
    		AddSigner(privateKey, subjectKeyID, GetEncOid(privateKey, digestOID), digestOID);
    	}

    	public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string encryptionOID, string digestOID)
    	{
    		doAddSigner(privateKey, CmsSignedGenerator.GetSignerIdentifier(subjectKeyID), encryptionOID, digestOID, new DefaultSignedAttributeTableGenerator(), null, null);
    	}

    	public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string digestOID, Org.BouncyCastle.Asn1.Cms.AttributeTable signedAttr, Org.BouncyCastle.Asn1.Cms.AttributeTable unsignedAttr)
    	{
    		AddSigner(privateKey, cert, GetEncOid(privateKey, digestOID), digestOID, signedAttr, unsignedAttr);
    	}

    	public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string encryptionOID, string digestOID, Org.BouncyCastle.Asn1.Cms.AttributeTable signedAttr, Org.BouncyCastle.Asn1.Cms.AttributeTable unsignedAttr)
    	{
    		doAddSigner(privateKey, CmsSignedGenerator.GetSignerIdentifier(cert), encryptionOID, digestOID, new DefaultSignedAttributeTableGenerator(signedAttr), new SimpleAttributeTableGenerator(unsignedAttr), signedAttr);
    	}

    	public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string digestOID, Org.BouncyCastle.Asn1.Cms.AttributeTable signedAttr, Org.BouncyCastle.Asn1.Cms.AttributeTable unsignedAttr)
    	{
    		AddSigner(privateKey, subjectKeyID, GetEncOid(privateKey, digestOID), digestOID, signedAttr, unsignedAttr);
    	}

    	public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string encryptionOID, string digestOID, Org.BouncyCastle.Asn1.Cms.AttributeTable signedAttr, Org.BouncyCastle.Asn1.Cms.AttributeTable unsignedAttr)
    	{
    		doAddSigner(privateKey, CmsSignedGenerator.GetSignerIdentifier(subjectKeyID), encryptionOID, digestOID, new DefaultSignedAttributeTableGenerator(signedAttr), new SimpleAttributeTableGenerator(unsignedAttr), signedAttr);
    	}

    	public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string digestOID, CmsAttributeTableGenerator signedAttrGen, CmsAttributeTableGenerator unsignedAttrGen)
    	{
    		AddSigner(privateKey, cert, GetEncOid(privateKey, digestOID), digestOID, signedAttrGen, unsignedAttrGen);
    	}

    	public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string encryptionOID, string digestOID, CmsAttributeTableGenerator signedAttrGen, CmsAttributeTableGenerator unsignedAttrGen)
    	{
    		doAddSigner(privateKey, CmsSignedGenerator.GetSignerIdentifier(cert), encryptionOID, digestOID, signedAttrGen, unsignedAttrGen, null);
    	}

    	public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string digestOID, CmsAttributeTableGenerator signedAttrGen, CmsAttributeTableGenerator unsignedAttrGen)
    	{
    		AddSigner(privateKey, subjectKeyID, GetEncOid(privateKey, digestOID), digestOID, signedAttrGen, unsignedAttrGen);
    	}

    	public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string encryptionOID, string digestOID, CmsAttributeTableGenerator signedAttrGen, CmsAttributeTableGenerator unsignedAttrGen)
    	{
    		doAddSigner(privateKey, CmsSignedGenerator.GetSignerIdentifier(subjectKeyID), encryptionOID, digestOID, signedAttrGen, unsignedAttrGen, null);
    	}

    	private void doAddSigner(AsymmetricKeyParameter privateKey, SignerIdentifier signerIdentifier, string encryptionOID, string digestOID, CmsAttributeTableGenerator signedAttrGen, CmsAttributeTableGenerator unsignedAttrGen, Org.BouncyCastle.Asn1.Cms.AttributeTable baseSignedTable)
    	{
    		signerInfs.Add(new SignerInf(this, privateKey, signerIdentifier, digestOID, encryptionOID, signedAttrGen, unsignedAttrGen, baseSignedTable));
    	}

    	public CmsSignedData Generate(CmsProcessable content)
    	{
    		return Generate(content, encapsulate: false);
    	}

    	public void PreGenerate(string signedContentType, CmsProcessable content)
    	{
    		Asn1EncodableVector asn1EncodableVector = new Asn1EncodableVector(new Asn1Encodable[0]);
    		Asn1EncodableVector asn1EncodableVector2 = new Asn1EncodableVector(new Asn1Encodable[0]);
    		_digests.Clear();
    		foreach (SignerInformation signer in _signers)
    		{
    			asn1EncodableVector.Add(Helper.FixAlgID(signer.DigestAlgorithmID));
    			asn1EncodableVector2.Add(signer.ToSignerInfo());
    		}
    		DerObjectIdentifier contentType = ((signedContentType == null) ? null : new DerObjectIdentifier(signedContentType));
    		foreach (SignerInf signerInf in signerInfs)
    		{
    			try
    			{
    				asn1EncodableVector.Add(signerInf.DigestAlgorithmID);
    				asn1EncodableVector2.Add(signerInf.ToSignerInfo(contentType, content, rand));
    			}
    			catch (IOException e)
    			{
    				throw new CmsException("encoding error.", e);
    			}
    			catch (InvalidKeyException e2)
    			{
    				throw new CmsException("key inappropriate for signature.", e2);
    			}
    			catch (SignatureException e3)
    			{
    				throw new CmsException("error creating signature.", e3);
    			}
    			catch (CertificateEncodingException e4)
    			{
    				throw new CmsException("error creating sid.", e4);
    			}
    		}
    	}

    	public CmsSignedData Generate(string signedContentType, CmsProcessable content, bool encapsulate)
    	{
    		Asn1EncodableVector asn1EncodableVector = new Asn1EncodableVector(new Asn1Encodable[0]);
    		Asn1EncodableVector asn1EncodableVector2 = new Asn1EncodableVector(new Asn1Encodable[0]);
    		_digests.Clear();
    		foreach (SignerInformation signer in _signers)
    		{
    			asn1EncodableVector.Add(Helper.FixAlgID(signer.DigestAlgorithmID));
    			asn1EncodableVector2.Add(signer.ToSignerInfo());
    		}
    		DerObjectIdentifier contentType = ((signedContentType == null) ? null : new DerObjectIdentifier(signedContentType));
    		foreach (object signerInf2 in signerInfs)
    		{
    			if (signerInf2 is ExternalSignatureSignerInfoGenerator)
    			{
    				ExternalSignatureSignerInfoGenerator externalSignatureSignerInfoGenerator = (ExternalSignatureSignerInfoGenerator)signerInf2;
    				AlgorithmIdentifier element = _makeAlgId(externalSignatureSignerInfoGenerator.digestOID, null);
    				asn1EncodableVector.Add(element);
    				asn1EncodableVector2.Add(externalSignatureSignerInfoGenerator.Generate());
    				continue;
    			}
    			try
    			{
    				SignerInf signerInf = (SignerInf)signerInf2;
    				asn1EncodableVector.Add(signerInf.DigestAlgorithmID);
    				asn1EncodableVector2.Add(signerInf.ToSignerInfo(contentType, content, rand));
    			}
    			catch (IOException e)
    			{
    				throw new CmsException("encoding error.", e);
    			}
    			catch (InvalidKeyException e2)
    			{
    				throw new CmsException("key inappropriate for signature.", e2);
    			}
    			catch (SignatureException e3)
    			{
    				throw new CmsException("error creating signature.", e3);
    			}
    			catch (CertificateEncodingException e4)
    			{
    				throw new CmsException("error creating sid.", e4);
    			}
    		}
    		Asn1Set certificates = null;
    		if (_certs.Count != 0)
    		{
    			certificates = Org.BouncyCastle.Cms.CmsUtilities.CreateBerSetFromList(_certs);
    		}
    		Asn1Set crls = null;
    		if (_crls.Count != 0)
    		{
    			crls = Org.BouncyCastle.Cms.CmsUtilities.CreateBerSetFromList(_crls);
    		}
    		Asn1OctetString content2 = null;
    		if (encapsulate)
    		{
                using (MemoryStream memoryStream = new MemoryStream()) { 
                    if (content != null)
                    {
                        try
                        {
                            content.Write(memoryStream);
                        }
                        catch (IOException e5)
                        {
                            throw new CmsException("encapsulation error.", e5);
                        }
                    }
    			    content2 = new DerOctetString(memoryStream.ToArray());
                }
            }
    		ContentInfo contentInfo = new ContentInfo(contentType, content2);
    		SignedData content3 = new SignedData(new DerSet(asn1EncodableVector), contentInfo, certificates, crls, new DerSet(asn1EncodableVector2));
    		ContentInfo sigData = new ContentInfo(CmsObjectIdentifiers.SignedData, content3);
    		return new CmsSignedData(content, sigData);
            
        }

    	public CmsSignedData Generate(CmsProcessable content, bool encapsulate)
    	{
    		return Generate(CmsSignedGenerator.Data, content, encapsulate);
    	}

    	public SignerInformationStore GenerateCounterSigners(SignerInformation signer)
    	{
    		return Generate(null, new CmsProcessableByteArray(signer.GetSignature()), encapsulate: false).GetSignerInfos();
    	}

    	private AlgorithmIdentifier _makeAlgId(string oid, byte[] paramss)
    	{
    		if (paramss == null)
    		{
    			return new AlgorithmIdentifier(new DerObjectIdentifier(oid), DerNull.Instance);
    		}
    		return new AlgorithmIdentifier(new DerObjectIdentifier(oid), _makeObj(paramss));
    	}

    	private Asn1Object _makeObj(byte[] encodeing)
    	{
    		if (encodeing != null)
    		{
    			return new Asn1InputStream(encodeing).ReadObject();
    		}
    		return null;
    	}
    }
}
