using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using SignService.Common.HashSignature.Common;
using SignService.Common.HashSignature.Interface;

namespace SignService.Common.HashSignature.Cms
{
    [Serializable]
    public class CmsHashSigner : BaseHashSigner, IHashSigner
    {
    	private Org.BouncyCastle.X509.X509Certificate _signer;

    	private List<Org.BouncyCastle.X509.X509Certificate> _certChain;

    	private HashAlgorithm _messageDigest;

    	private HashAlgorithmName _messageDigestName;

    	private string _messageDigestAlg = "SHA1";

    	private bool _encapsulate;

    	private ExternalSignatureSignerInfoGenerator signerGenerator;

    	private readonly CustomCMSSignedDataGenerator _gen = new CustomCMSSignedDataGenerator();

    	private string _digestAlgOid;

    	public CmsHashSigner()
    	{
    	}

    	public CmsHashSigner(byte[] unsignedData, string certBase64)
    		: base(unsignedData, certBase64)
    	{
    		try
    		{
    			X509CertificateParser x509CertificateParser = new X509CertificateParser();
    			_signer = x509CertificateParser.ReadCertificate(Convert.FromBase64String(certBase64));
    			_certChain = new List<Org.BouncyCastle.X509.X509Certificate>();
    			_certChain.Add(_signer);
    		}
    		catch (Exception ex)
    		{
    			ex.LogExceptionToFile();
    		}
    	}

    	public CmsHashSigner(byte[] unsignedData, byte[] certBytes)
    		: base(unsignedData, certBytes)
    	{
    		try
    		{
    			X509CertificateParser x509CertificateParser = new X509CertificateParser();
    			_signer = x509CertificateParser.ReadCertificate(certBytes);
    			_certChain = new List<Org.BouncyCastle.X509.X509Certificate>();
    			_certChain.Add(_signer);
    		}
    		catch (Exception ex)
    		{
    			ex.LogExceptionToFile();
    		}
    	}

    	private void CalculateSignature()
    	{
    		switch (_hashAlgorithm)
    		{
    		case MessageDigestAlgorithm.SHA1:
    			_digestAlgOid = CmsSignedGenerator.DigestSha1;
    			_messageDigest = SHA1.Create();
    			_messageDigestAlg = "SHA1";
    			_messageDigestName = HashAlgorithmName.SHA1;
    			break;
    		case MessageDigestAlgorithm.SHA256:
    			_digestAlgOid = CmsSignedGenerator.DigestSha256;
    			_messageDigest = SHA256.Create();
    			_messageDigestAlg = "SHA256";
    			_messageDigestName = HashAlgorithmName.SHA256;
    			break;
    		default:
    			_digestAlgOid = CmsSignedGenerator.DigestSha1;
    			_messageDigest = SHA1.Create();
    			_messageDigestAlg = "SHA1";
    			_messageDigestName = HashAlgorithmName.SHA1;
    			break;
    		}
    		signerGenerator = new ExternalSignatureSignerInfoGenerator(_digestAlgOid, CmsSignedGenerator.EncryptionRsa)
    		{
    			cert = _signer
    		};
    	}

    	public bool CheckHashSignature(byte[] hashValue, string signedHashBase64)
    	{
    		return false;
    	}

    	public bool CheckHashSignature(string signedHashBase64)
    	{
    		try
    		{
    			byte[] signature = Convert.FromBase64String(signedHashBase64);
    			return new X509Certificate2(_signerCert).GetRSAPublicKey().VerifyData(_secondHash, signature, _messageDigestName, RSASignaturePadding.Pkcs1);
    		}
    		catch (Exception ex)
    		{
    			ex.LogExceptionToFile();
    			return false;
    		}
    	}

    	public bool CheckHashSignature(byte[] signedBytes)
    	{
    		try
    		{
    			return new X509Certificate2(_signerCert).GetRSAPublicKey().VerifyData(_secondHash, signedBytes, _messageDigestName, RSASignaturePadding.Pkcs1);
    		}
    		catch (Exception ex)
    		{
    			ex.LogExceptionToFile();
    			return false;
    		}
    	}

    	public string GetSecondHashAsBase64()
    	{
    		try
    		{
    			return Convert.ToBase64String(GetSecondHashBytes());
    		}
    		catch (Exception ex)
    		{
    			ex.LogExceptionToFile();
    			return null;
    		}
    	}

    	public byte[] GetSecondHashBytes()
    	{
    		CalculateSignature();
    		CmsProcessable msg = new CmsProcessableByteArray(_unsignData);
    		_secondHash = signerGenerator.GetBytesToSign(PkcsObjectIdentifiers.Data, msg, DateTime.UtcNow, "BC");
    		return _messageDigest.ComputeHash(_secondHash);
    	}

    	public void SetHashAlgorithm(MessageDigestAlgorithm alg)
    	{
    		_hashAlgorithm = alg;
    	}

    	public byte[] Sign(string signedHashBase64)
    	{
    		try
    		{
    			byte[] signedBytes = Convert.FromBase64String(signedHashBase64);
    			return Sign(signedBytes);
    		}
    		catch (Exception ex)
    		{
    			ex.LogExceptionToFile();
    			return null;
    		}
    	}

    	public byte[] Sign(byte[] signedBytes)
    	{
    		if (signedBytes == null || signedBytes.Length == 0)
    		{
    			LogFile.LogToFile("CmsHashSigner.Sign(): signedBytes is null");
    			return null;
    		}
    		signerGenerator.signedBytes = signedBytes;
    		_gen.AddSigner(signerGenerator);
    		IX509Store certStore = X509StoreFactory.Create("Certificate/Collection", new X509CollectionStoreParameters(_certChain));
    		_gen.AddCertificates(certStore);
    		CmsProcessable content = new CmsProcessableByteArray(_unsignData);
    		return _gen.Generate(content, _encapsulate).GetEncoded();
    	}

    	public bool SetSignerCertchain(string pkcs7Base64)
    	{
    		if (string.IsNullOrEmpty(pkcs7Base64))
    		{
    			LogFile.LogToFile("CmsHashSigner.SetSignerCertchain(): pkcs7Base64 null");
    			return false;
    		}
    		if (pkcs7Base64.StartsWith("-----BEGIN PKCS7-----"))
    		{
    			pkcs7Base64 = pkcs7Base64.Replace("-----BEGIN PKCS7-----", "").Replace("-----END PKCS7-----", "").Replace("\n", "")
    				.Replace("\r", "");
    		}
    		try
    		{
    			ArrayList arrayList = new ArrayList(new CmsSignedData(Convert.FromBase64String(pkcs7Base64)).GetCertificates("Collection").GetMatches(null));
    			_ = (Org.BouncyCastle.X509.X509Certificate)arrayList[0];
    			_certChain = new List<Org.BouncyCastle.X509.X509Certificate>();
    			foreach (object item in arrayList)
    			{
    				_certChain.Add((Org.BouncyCastle.X509.X509Certificate)item);
    			}
    			if (_certChain[0].SubjectDN.Equals(_certChain[0].IssuerDN))
    			{
    				_certChain.Reverse();
    			}
    			_signer = _certChain[0];
    			_signerCert = _signer.GetEncoded();
    			return true;
    		}
    		catch (Exception ex)
    		{
    			LogFile.LogToFile("CmsHashSigner.SetSignerCertchain(): " + ex.Message);
    			return false;
    		}
    	}

    	public bool SetSignerCertchain(ICollection<string> certs)
    	{
    		if (certs != null)
    		{
    			foreach (string cert in certs)
    			{
    				if (string.IsNullOrEmpty(cert))
    				{
    					LogFile.LogToFile("PdfHashSigner.SetSignerCertchain(): certBase64 null");
    					return false;
    				}
    				string text = cert.Trim();
    				if (text.StartsWith("-----BEGIN CERTIFICATE-----"))
    				{
    					text = text.Replace("-----BEGIN CERTIFICATE-----", "").Replace("-----END CERTIFICATE-----", "");
    				}
    				try
    				{
    					Org.BouncyCastle.X509.X509Certificate item = new X509CertificateParser().ReadCertificate(Convert.FromBase64String(cert));
    					_certChain.Add(item);
    				}
    				catch (Exception ex)
    				{
    					LogFile.LogToFile("PdfHashSigner.SetSignerCertchain(): read certificate failed" + ex.Message);
    					return false;
    				}
    			}
    			if (_certChain[0].SubjectDN.Equals(_certChain[0].IssuerDN))
    			{
    				_certChain.Reverse();
    			}
    			_signer = _certChain[0];
    			_signerCert = _signer.GetEncoded();
    			return true;
    		}
    		return false;
    	}

    	public string GetSignerSubjectDN()
    	{
    		try
    		{
    			return _signer.SubjectDN.ToString();
    		}
    		catch (Exception)
    		{
    			return null;
    		}
    	}

    	public void SetOcspRespnse(byte[] ocsp)
    	{
    		throw new NotImplementedException();
    	}

    	public void SetCrlResponse(ICollection<byte[]> clrs)
    	{
    		throw new NotImplementedException();
    	}

    	public void SetEncapsulate(bool isEncapsulate)
    	{
    		_encapsulate = isEncapsulate;
    	}

    	public void EnableLTV(ICollection<byte[]> ocsps, ICollection<byte[]> clrs)
    	{
    		throw new NotImplementedException();
    	}

    	public void EnableLTV(bool addDocumentLvTimestamp)
    	{
    		throw new NotImplementedException();
    	}

    	public SignerProfile GetSignerProfile()
    	{
    		byte[] array = null;
    		try
    		{
    			array = GetSecondHashBytes();
    		}
    		catch (Exception)
    		{
    			throw;
    		}
    		return new SignerProfile
    		{
    			DocType = "CMS",
    			HashAlgorithm = _digestAlgOid,
    			SecondHashBytes = array,
    			TempData = _unsignData,
    			DataHashBytes = signerGenerator.signedAttr.GetEncoded(),
    			Certchain = _certChain?.Select((Org.BouncyCastle.X509.X509Certificate c) => c.GetEncoded()).ToList(),
    			IsPades = _encapsulate
    		};
    	}

    	public byte[] Sign(SignerProfile profile, byte[] signedBytes)
    	{
    		X509CertificateParser parser = new X509CertificateParser();
    		_certChain = profile.Certchain.Select((byte[] c) => parser.ReadCertificate(c)).ToList();
    		signerGenerator = new ExternalSignatureSignerInfoGenerator(profile.HashAlgorithm, CmsSignedGenerator.EncryptionRsa)
    		{
    			cert = _certChain.First()
    		};
    		signerGenerator.signedAttr = Asn1Set.GetInstance(profile.DataHashBytes);
    		signerGenerator.signedBytes = signedBytes;
    		_gen.AddSigner(signerGenerator);
    		IX509Store certStore = X509StoreFactory.Create("Certificate/Collection", new X509CollectionStoreParameters(_certChain));
    		_gen.AddCertificates(certStore);
    		CmsProcessable content = new CmsProcessableByteArray(profile.TempData);
    		return _gen.Generate(content, profile.IsPades).GetEncoded();
    	}

    	public bool CheckHashSignature(SignerProfile profile, byte[] signedBytes)
    	{
    		return true;
    	}

    	public void EnableTimestamp()
    	{
    		_enableTimestamp = true;
    	}
    }
}
