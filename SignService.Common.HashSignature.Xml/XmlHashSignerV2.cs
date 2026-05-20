using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using SignService.Common.HashSignature.Common;
using SignService.Common.HashSignature.Interface;

namespace SignService.Common.HashSignature.Xml;

public class XmlHashSignerV2 : BaseHashSigner, IHashSigner
{
	private string _referenceId = "";

	private IList<string?> _referenceIds;

	private string _xpath;

	private bool _signUsingXpath;

	private string _parentNode = "";

	private string _nameSpace = "";

	private DateTime _signingTime = DateTime.UtcNow;

	private string _signTimeId = "signingtime";

	private bool _addSigningTimeReference;

	private string _nameSpaceRef = "";

	private string _signatureId = "signid";

	private X509Certificate _signer;

	private ICollection<X509Certificate> _certificates;

	private XmlDocument _doc;

	private LTV_Level _ltvLevel;

	private bool _isXades;

	public XmlHashSignerV2()
	{
	}

	public void SetSignerCertificate(string certBase64)
	{
		if (!string.IsNullOrEmpty(certBase64))
		{
			if (certBase64.StartsWith("-----BEGIN CERTIFICATE-----"))
			{
				certBase64 = certBase64.Replace("-----BEGIN CERTIFICATE-----", "").Replace("-----END CERTIFICATE-----", "");
			}
			_signerCert = Convert.FromBase64String(certBase64);
			Init();
		}
	}

	public void SetUnsignData(string base64Data)
	{
		_unsignData = Convert.FromBase64String(base64Data);
	}

	public string SignBase64(string signedHashBase64)
	{
		byte[] array = Sign(signedHashBase64);
		if (array != null)
		{
			return Convert.ToBase64String(array);
		}
		Console.WriteLine("Error when package signed data");
		return null;
	}

	public XmlHashSignerV2(byte[] unsignData, string certBase64)
		: base(unsignData, certBase64)
	{
		Init();
	}

	public XmlHashSignerV2(byte[] unsignData, byte[] certBytes)
		: base(unsignData, certBytes)
	{
		Init();
	}

	private void Init()
	{
		try
		{
			_signer = new X509Certificate(_signerCert);
		}
		catch (Exception)
		{
		}
		_doc = new XmlDocument();
		XmlReaderSettings settings = new XmlReaderSettings
		{
			CloseInput = true,
			IgnoreComments = false,
			IgnoreWhitespace = false,
			IgnoreProcessingInstructions = true
		};
		using Stream input = new MemoryStream(_unsignData);
		try
		{
			XmlReader xmlReader = XmlReader.Create(input, settings);
			_doc.Load(xmlReader);
			xmlReader.Close();
		}
		catch (Exception)
		{
		}
	}

	public bool CheckHashSignature(byte[] signedBytes)
	{
		throw new NotImplementedException();
	}

	public bool CheckHashSignature(byte[] hashValue, string signedHashBase64)
	{
		return false;
	}

	public bool CheckHashSignature(string signedHashBase64)
	{
		byte[] signature = Convert.FromBase64String(signedHashBase64);
		return new X509Certificate2(_signerCert).GetRSAPublicKey().VerifyHash(_secondHash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
	}

	public bool CheckHashSignature(SignerProfile profile, byte[] signedBytes)
	{
		_signerCert = profile.Certchain.FirstOrDefault();
		return ((RSACng)new X509Certificate2(_signerCert).PublicKey.Key).VerifyHash(profile.SecondHashBytes, signedBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
	}

	public void EnableLTV(ICollection<byte[]> ocsps, ICollection<byte[]> clrs)
	{
		throw new NotImplementedException();
	}

	public void EnableLTV(bool addDocumentLvTimestamp)
	{
		throw new NotImplementedException();
	}

	public void EnableTimestamp()
	{
		throw new NotImplementedException();
	}

	public void EnableLTV(LTV_Level level)
	{
		_ltvLevel = level;
		_isXades = true;
	}

	public void EnableLTV(LTV_Level level, string tsaUrl, string tsaUser, string tsaPass)
	{
		_ltvLevel = level;
		_isXades = true;
		_tsaUrl = tsaUrl;
		_tsaUsername = tsaUser;
		_tsaPassword = tsaPass;
	}

	public string GetSecondHashAsBase64()
	{
		throw new NotImplementedException();
	}

	private static string _getDigestMethod(MessageDigestAlgorithm alg)
	{
		return alg switch
		{
			MessageDigestAlgorithm.SHA1 => "http://www.w3.org/2000/09/xmldsig#sha1", 
			MessageDigestAlgorithm.SHA256 => "http://www.w3.org/2001/04/xmlenc#sha256", 
			MessageDigestAlgorithm.SHA384 => "http://www.w3.org/2001/04/xmldsig-more#sha384", 
			MessageDigestAlgorithm.SHA512 => "http://www.w3.org/2001/04/xmlenc#sha512", 
			_ => "http://www.w3.org/2001/04/xmlenc#sha256", 
		};
	}

	private static string _getSignatureAlg(MessageDigestAlgorithm alg)
	{
		return alg switch
		{
			MessageDigestAlgorithm.SHA1 => "http://www.w3.org/2000/09/xmldsig#rsa-sha1", 
			MessageDigestAlgorithm.SHA256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", 
			MessageDigestAlgorithm.SHA384 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", 
			MessageDigestAlgorithm.SHA512 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", 
			_ => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", 
		};
	}

	public static void AddSignatureNode(XmlDocument doc, XmlNode signature, string parentNodePath, string nameSpace, string nameSpaceRef)
	{
		XmlNode newChild = doc.ImportNode(signature, deep: true);
		if (string.IsNullOrEmpty(parentNodePath))
		{
			doc.DocumentElement.AppendChild(newChild);
			return;
		}
		XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(doc.NameTable);
		if (!string.IsNullOrEmpty(nameSpace) && !string.IsNullOrEmpty(nameSpaceRef))
		{
			xmlNamespaceManager.AddNamespace(nameSpace, nameSpaceRef);
		}
		(((XmlElement)doc.SelectSingleNode(parentNodePath, xmlNamespaceManager)) ?? throw new Exception("No parent node in document. node name=" + parentNodePath)).AppendChild(newChild);
	}

	private static XmlDsigXPathTransform CreateXPathTransform(string XPathString)
	{
		XmlElement xmlElement = new XmlDocument().CreateElement("XPath");
		xmlElement.InnerText = XPathString;
		XmlDsigXPathTransform xmlDsigXPathTransform = new XmlDsigXPathTransform();
		xmlDsigXPathTransform.LoadInnerXml(xmlElement.SelectNodes("."));
		return xmlDsigXPathTransform;
	}

	public byte[] GetSecondHashBytes()
	{
		RemoteSignedXml remoteSignedXml = new RemoteSignedXml(_doc, _getSignatureAlg(_hashAlgorithm));
		if (_referenceIds != null)
		{
			foreach (string referenceId in _referenceIds)
			{
				string uri = "";
				if (!string.IsNullOrEmpty(referenceId))
				{
					uri = referenceId;
					if (!referenceId.StartsWith("#"))
					{
						uri = "#" + referenceId;
					}
				}
				ReferenceCustom referenceCustom = new ReferenceCustom
				{
					Uri = uri,
					DigestMethod = _getDigestMethod(_hashAlgorithm)
				};
				XmlDsigEnvelopedSignatureTransform transform = new XmlDsigEnvelopedSignatureTransform();
				referenceCustom.AddTransform(transform);
				remoteSignedXml.AddReference(referenceCustom);
			}
		}
		else if (!string.IsNullOrEmpty(_referenceId))
		{
			string text = "";
			if (!_referenceId.StartsWith("#"))
			{
				_referenceId = "#" + _referenceId;
			}
			text = _referenceId;
			ReferenceCustom referenceCustom2 = new ReferenceCustom
			{
				Uri = text,
				DigestMethod = _getDigestMethod(_hashAlgorithm)
			};
			XmlDsigEnvelopedSignatureTransform transform2 = new XmlDsigEnvelopedSignatureTransform();
			referenceCustom2.AddTransform(transform2);
			remoteSignedXml.AddReference(referenceCustom2);
		}
		else
		{
			ReferenceCustom referenceCustom3 = new ReferenceCustom
			{
				Uri = "",
				DigestMethod = _getDigestMethod(_hashAlgorithm)
			};
			XmlDsigEnvelopedSignatureTransform transform3 = new XmlDsigEnvelopedSignatureTransform();
			referenceCustom3.AddTransform(transform3);
			remoteSignedXml.AddReference(referenceCustom3);
		}
		KeyInfo keyInfo = new KeyInfo();
		KeyInfoX509Data keyInfoX509Data = new KeyInfoX509Data(_signer);
		X509Certificate x509Certificate = null;
		if (_certificates != null && _signer.Issuer != _signer.Subject)
		{
			foreach (X509Certificate certificate in _certificates)
			{
				if (certificate.Subject == _signer.Issuer)
				{
					x509Certificate = certificate;
				}
			}
		}
		if (x509Certificate != null)
		{
			BigInteger bigInteger = new BigInteger(x509Certificate.GetSerialNumber());
			keyInfoX509Data.AddIssuerSerial(x509Certificate.Subject, bigInteger.ToString(10));
		}
		keyInfoX509Data.AddSubjectName(_signer.Subject);
		keyInfo.AddClause(new RSAKeyValue(new X509Certificate2(_signer.GetRawCertData()).GetRSAPublicKey()));
		keyInfo.AddClause(keyInfoX509Data);
		remoteSignedXml.KeyInfo = keyInfo;
		remoteSignedXml.Signature.Id = _signatureId.ToString();
		XmlElement xmlElement = _doc.CreateElement("SignatureProperties");
		xmlElement.SetAttribute("Id", "proid");
		xmlElement.SetAttribute("xmlns", "");
		XmlElement xmlElement2 = _doc.CreateElement("SignatureProperty");
		xmlElement2.SetAttribute("Target", "#" + _signatureId);
		XmlElement xmlElement3 = _doc.CreateElement("SigningTime");
		xmlElement3.SetAttribute("xmlns", "http://example.org/#signatureProperties");
		XmlNode newChild = _doc.CreateTextNode(DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ssZ"));
		xmlElement3.AppendChild(newChild);
		xmlElement.AppendChild(xmlElement2);
		xmlElement2.AppendChild(xmlElement3);
		string text2 = "signingtime-" + _signatureId;
		DataObjectCustom dataObject = new DataObjectCustom
		{
			Data = xmlElement.SelectNodes(".")
		};
		remoteSignedXml.AddObject(dataObject);
		if (_addSigningTimeReference)
		{
			ReferenceCustom reference = new ReferenceCustom
			{
				Uri = "#" + text2,
				DigestMethod = _getDigestMethod(_hashAlgorithm)
			};
			remoteSignedXml.AddReference(reference);
		}
		byte[] hashValue = remoteSignedXml.GetHashValue();
		remoteSignedXml.Sign(Array.Empty<byte>());
		string outerXml = remoteSignedXml.GetXml().OuterXml;
		_signerInfoData = Encoding.UTF8.GetBytes(outerXml);
		AddSignatureNode(_doc, remoteSignedXml.GetXml(), _parentNode, _nameSpace, _nameSpaceRef);
		return hashValue;
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
		SignerProfile signerProfile = new SignerProfile();
		signerProfile.DocType = "XML";
		signerProfile.SecondHashBytes = array;
		signerProfile.TempData = Encoding.UTF8.GetBytes(_doc.OuterXml.Replace("\r", "&#13;"));
		signerProfile.Certchain = new byte[1][] { _signerCert };
		signerProfile.HashAlgorithm = _hashAlgorithm.ToString();
		signerProfile.IsPades = _isXades;
		signerProfile.TsaUrl = _tsaUrl;
		signerProfile.TsaUsername = _tsaUsername;
		signerProfile.TsaPassword = _tsaPassword;
		signerProfile.Fieldnames = new List<string> { _signatureId };
		return signerProfile;
	}

	public string GetSignerSubjectDN()
	{
		throw new NotImplementedException();
	}

	public void SetCrlResponse(ICollection<byte[]> clrs)
	{
		throw new NotImplementedException();
	}

	public void SetHashAlgorithm(MessageDigestAlgorithm alg)
	{
		_hashAlgorithm = alg;
	}

	public void SetSignatureID(string value)
	{
		_signatureId = value;
	}

	public void SetReferenceId(string id)
	{
		_referenceId = id;
	}

	public void SetReferenceIds(IList<string?> ids)
	{
		_referenceIds = ids;
	}

	public void SetXpath(string expression)
	{
		_xpath = expression;
		_signUsingXpath = true;
	}

	public void SetParentNodePath(string node)
	{
		_parentNode = node;
	}

	public void SetOcspRespnse(byte[] ocsp)
	{
		throw new NotImplementedException();
	}

	public void SetSignatureParam(XMLSignauterParam param)
	{
		if (param != null)
		{
			if (!string.IsNullOrEmpty(param.Namespace) && !string.IsNullOrEmpty(param.NamespaceRef))
			{
				SetNameSpace(param.Namespace, param.NamespaceRef);
			}
			if (!string.IsNullOrEmpty(param.ParentNodePath))
			{
				SetParentNodePath(param.ParentNodePath);
			}
			if (!string.IsNullOrEmpty(param.ReferenceId))
			{
				SetReferenceId(param.ReferenceId);
			}
			if (!string.IsNullOrEmpty(param.SignatureId))
			{
				SetSignatureID(param.SignatureId);
			}
		}
	}

	public void SetNameSpace(string nameSpace, string reference)
	{
		_nameSpace = nameSpace;
		_nameSpaceRef = reference;
	}

	public bool SetSignerCertchain(string pkcs7Base64)
	{
		return false;
	}

	public bool SetSignerCertchain(ICollection<string> certs)
	{
		_certificates = new Collection<X509Certificate> { _signer };
		foreach (string cert in certs)
		{
			try
			{
				_certificates.Add(new X509Certificate(Convert.FromBase64String(cert)));
			}
			catch (Exception)
			{
				throw;
			}
		}
		return true;
	}

	public byte[] Sign(string signedHashBase64)
	{
		throw new NotImplementedException();
	}

	public byte[] Sign(byte[] signedBytes)
	{
		throw new NotImplementedException();
	}

	public byte[] Sign(SignerProfile profile, byte[] signedBytes)
	{
		_doc = new XmlDocument();
		XmlReaderSettings settings = new XmlReaderSettings
		{
			CloseInput = true,
			IgnoreComments = false,
			IgnoreWhitespace = false,
			IgnoreProcessingInstructions = true
		};
		using (Stream input = new MemoryStream(profile.TempData))
		{
			try
			{
				XmlReader xmlReader = XmlReader.Create(input, settings);
				_doc.Load(xmlReader);
				xmlReader.Close();
			}
			catch (Exception)
			{
				throw;
			}
		}
		string xpath = $"//*[@Id='{profile.Fieldnames.FirstOrDefault()}']";
		XmlElement xmlElement = (XmlElement)_doc.SelectSingleNode(xpath);
		((XmlElement)xmlElement.GetElementsByTagName("SignatureValue")[0]).InnerText = Convert.ToBase64String(signedBytes);
		if (profile.IsPades)
		{
			AddXadesProperties(xmlElement, profile.Certchain.ElementAt(0));
			AddTimestampAsync(xmlElement, profile.TsaUrl, profile.TsaUsername, profile.TsaPassword).GetAwaiter().GetResult();
		}
		return Encoding.UTF8.GetBytes(_doc.OuterXml.Replace("\r", "&#13;"));
	}

	private void AddXadesProperties(XmlElement signature, byte[] signerCertBytes)
	{
		XmlElement xmlElement = signature.OwnerDocument.CreateElement("QualifyingProperties", "http://uri.etsi.org/01903/v1.3.2#");
		xmlElement.SetAttribute("Target", "#" + signature.GetAttribute("Id"));
		XmlElement xmlElement2 = signature.OwnerDocument.CreateElement("SignedProperties", "http://uri.etsi.org/01903/v1.3.2#");
		xmlElement2.SetAttribute("Id", "SignedProperties");
		XmlElement xmlElement3 = signature.OwnerDocument.CreateElement("SignedSignatureProperties", "http://uri.etsi.org/01903/v1.3.2#");
		XmlElement xmlElement4 = signature.OwnerDocument.CreateElement("SigningTime", "http://uri.etsi.org/01903/v1.3.2#");
		xmlElement4.InnerText = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
		xmlElement3.AppendChild(xmlElement4);
		XmlElement xmlElement5 = signature.OwnerDocument.CreateElement("SigningCertificate", "http://uri.etsi.org/01903/v1.3.2#");
		XmlElement xmlElement6 = signature.OwnerDocument.CreateElement("Cert", "http://uri.etsi.org/01903/v1.3.2#");
		XmlElement xmlElement7 = signature.OwnerDocument.CreateElement("CertDigest", "http://uri.etsi.org/01903/v1.3.2#");
		XmlElement xmlElement8 = signature.OwnerDocument.CreateElement("DigestMethod", "http://www.w3.org/2000/09/xmldsig#");
		xmlElement8.SetAttribute("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha256");
		XmlElement xmlElement9 = signature.OwnerDocument.CreateElement("DigestValue", "http://www.w3.org/2000/09/xmldsig#");
		using (SHA256 sHA = SHA256.Create())
		{
			xmlElement9.InnerText = Convert.ToBase64String(sHA.ComputeHash(signerCertBytes));
		}
		xmlElement7.AppendChild(xmlElement8);
		xmlElement7.AppendChild(xmlElement9);
		xmlElement6.AppendChild(xmlElement7);
		xmlElement5.AppendChild(xmlElement6);
		xmlElement3.AppendChild(xmlElement5);
		xmlElement2.AppendChild(xmlElement3);
		xmlElement.AppendChild(xmlElement2);
		XmlNode xmlNode = signature.SelectSingleNode("ds:Object", GetNamespaceManager(signature.OwnerDocument));
		if (xmlNode == null)
		{
			xmlNode = signature.OwnerDocument.CreateElement("Object", "http://www.w3.org/2000/09/xmldsig#");
			signature.AppendChild(xmlNode);
		}
		xmlNode.AppendChild(xmlElement);
	}

	private async Task AddTimestampAsync(XmlElement signature, string tsaUrl, string tsaUsername, string tsaPassword)
	{
		string obj = signature.SelectSingleNode("//ds:SignatureValue", GetNamespaceManager(signature.OwnerDocument))?.InnerText;
		if (string.IsNullOrEmpty(obj))
		{
			throw new Exception("Signature value not found.");
		}
		byte[] buffer = Convert.FromBase64String(obj);
		byte[] hashedMessage;
		using (SHA256 sHA = SHA256.Create())
		{
			hashedMessage = sHA.ComputeHash(buffer);
		}
		MessageImprint messageImprint = new MessageImprint(new AlgorithmIdentifier(new DerObjectIdentifier("2.16.840.1.101.3.4.2.1")), hashedMessage);
		DerInteger nonce = new DerInteger(BigInteger.ValueOf(DateTime.Now.Ticks));
		byte[] encoded = new TimeStampReq(messageImprint, null, nonce, DerBoolean.True, null).GetEncoded();
		using HttpClient client = new HttpClient();
		ByteArrayContent byteArrayContent = new ByteArrayContent(encoded);
		if (!string.IsNullOrEmpty(tsaUsername) && !string.IsNullOrEmpty(tsaPassword))
		{
			string parameter = Convert.ToBase64String(Encoding.UTF8.GetBytes(tsaUsername + ":" + tsaPassword));
			client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", parameter);
		}
		byteArrayContent.Headers.Add("Content-Type", "application/timestamp-query");
		byte[] inArray = await (await client.PostAsync(tsaUrl, byteArrayContent)).Content.ReadAsByteArrayAsync();
		XmlElement xmlElement = signature.OwnerDocument.CreateElement("UnsignedProperties", "http://uri.etsi.org/01903/v1.3.2#");
		XmlElement xmlElement2 = signature.OwnerDocument.CreateElement("UnsignedSignatureProperties", "http://uri.etsi.org/01903/v1.3.2#");
		XmlElement xmlElement3 = signature.OwnerDocument.CreateElement("SignatureTimeStamp", "http://uri.etsi.org/01903/v1.3.2#");
		XmlElement xmlElement4 = signature.OwnerDocument.CreateElement("EncapsulatedTimeStamp", "http://uri.etsi.org/01903/v1.3.2#");
		xmlElement4.InnerText = Convert.ToBase64String(inArray);
		xmlElement3.AppendChild(xmlElement4);
		xmlElement2.AppendChild(xmlElement3);
		xmlElement.AppendChild(xmlElement2);
		signature.SelectSingleNode("//xades:QualifyingProperties", GetNamespaceManager(signature.OwnerDocument))?.AppendChild(xmlElement);
	}

	private XmlNamespaceManager GetNamespaceManager(XmlDocument doc)
	{
		XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(doc.NameTable);
		xmlNamespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
		xmlNamespaceManager.AddNamespace("xades", "http://uri.etsi.org/01903/v1.3.2#");
		return xmlNamespaceManager;
	}

	private static XmlElement GetElement(string xml)
	{
		XmlDocument xmlDocument = new XmlDocument();
		xmlDocument.LoadXml(xml);
		return xmlDocument.DocumentElement;
	}
}
