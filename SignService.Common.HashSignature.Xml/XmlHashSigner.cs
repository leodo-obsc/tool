using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using Org.BouncyCastle.X509;
using SignService.Common.HashSignature.Common;
using SignService.Common.HashSignature.Exceptions;
using SignService.Common.HashSignature.Interface;

namespace SignService.Common.HashSignature.Xml
{
    public class XmlHashSigner : BaseHashSigner, IHashSigner
    {
    	private string _referenceId = "";

    	private List<string> _referencesId = new List<string>();

    	private string _parentNode = "";

    	private string _nameSpace = "";

    	private DateTime _signingTime = DateTime.UtcNow;

    	private string _signTimeId = "AddSigningTime";

    	private bool _addSigningTime;

    	private string _nameSpaceRef = "";

    	private string _signId = "signId";

    	private Org.BouncyCastle.X509.X509Certificate _signer;

    	private XmlDocument _doc;

    	private bool _versionXML11;

    	public XmlHashSigner()
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
    			try
    			{
    				X509CertificateParser x509CertificateParser = new X509CertificateParser();
    				_signer = x509CertificateParser.ReadCertificate(Convert.FromBase64String(certBase64));
    			}
    			catch (Exception)
    			{
    			}
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

    	public XmlHashSigner(byte[] unsignData, string certBase64)
    		: base(unsignData, certBase64)
    	{
    		Init();
    	}

    	public XmlHashSigner(byte[] unsignData, byte[] certBytes)
    		: base(unsignData, certBytes)
    	{
    		Init();
    	}

    	private void Init()
    	{
    		_signId = Guid.NewGuid().ToString();
    		_doc = new XmlDocument();
    		XmlReaderSettings settings = new XmlReaderSettings
    		{
    			CloseInput = true,
    			IgnoreComments = false,
    			IgnoreWhitespace = false,
    			IgnoreProcessingInstructions = true
    		};
    		if (_unsignData[0] == 60 && _unsignData[1] == 63 && _unsignData[2] == 120 && _unsignData[3] == 109 && 
                _unsignData[4] == 108 && _unsignData[5] == 32 && _unsignData[6] == 118 && _unsignData[7] == 101 && 
                _unsignData[8] == 114 && _unsignData[9] == 115 && _unsignData[10] == 105 && _unsignData[11] == 111 &&
                _unsignData[12] == 110 && _unsignData[13] == 61 && _unsignData[14] == 34 && _unsignData[15] == 49 && 
                _unsignData[16] == 46 && _unsignData[17] == 49 && _unsignData[18] == 34)
    		{
    			_versionXML11 = true;
    			_unsignData[17] = 48;
    		}
            using (Stream input = new MemoryStream(_unsignData)) { 
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
        }

    	public bool CheckHashSignature(string signedHashBase64)
    	{
    		byte[] signature = Convert.FromBase64String(signedHashBase64);
    		return new X509Certificate2(_signerCert).GetRSAPublicKey().VerifyHash(_secondHash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    	}

    	public string GetSecondHashAsBase64()
    	{
    		byte[] secondHashBytes = GetSecondHashBytes();
    		if (secondHashBytes == null)
    		{
    			return null;
    		}
    		return Convert.ToBase64String(secondHashBytes);
    	}

    	public byte[] GetSecondHashBytes()
    	{
    		try
    		{
    			HashAlgorithm alg = SHA1.Create();
    			switch (_hashAlgorithm)
    			{
    			case MessageDigestAlgorithm.SHA256:
    				alg = SHA256.Create();
    				break;
    			case MessageDigestAlgorithm.SHA384:
    				alg = SHA384.Create();
    				break;
    			case MessageDigestAlgorithm.SHA512:
    				alg = SHA512.Create();
    				break;
    			}
    			X509Certificate2 x509Certificate = new X509Certificate2(_signerCert);
    			string text = "";
    			text = x509Certificate.GetRSAPublicKey().ToXmlString(includePrivateParameters: false);

                //loido: change here
                string subjectDN = x509Certificate.SubjectName.Decode(X500DistinguishedNameFlags.None); 
                string nguoiKy = x509Certificate.GetNameInfo(X509NameType.SimpleName, false);

                XmlNodeList elementsByTagName = _doc.GetElementsByTagName("Signature");
    			if (elementsByTagName != null && elementsByTagName.Count > 0)
    			{
    				foreach (XmlElement item in elementsByTagName)
    				{
    					if (_signId.Equals(item.Attributes["Id"]?.Value))
    					{
    						throw new HashCalculateFailureException("Signature element with id " + _signId + " already exist");
    					}
    					if (_signId.Equals(item.Attributes["id"]?.Value))
    					{
    						throw new HashCalculateFailureException("Signature element with id " + _signId + " already exist");
    					}
    					if (_signId.Equals(item.Attributes["iD"]?.Value))
    					{
    						throw new HashCalculateFailureException("Signature element with id " + _signId + " already exist");
    					}
    					if (_signId.Equals(item.Attributes["ID"]?.Value))
    					{
    						throw new HashCalculateFailureException("Signature element with id " + _signId + " already exist");
    					}
    				}
    			}
    			List<string> list = new List<string>();
    			List<string> list2 = new List<string>();
    			string text2 = null;
    			XmlNode signature;
    			if (_referencesId.Count == 0)
    			{
    				text2 = Convert.ToBase64String(DsigSignature.GetC14NDigest(_doc, alg));
    				signature = DsigSignature.CreateSignature(_hashAlgorithm, _addSigningTime ? _signingTime : DateTime.MinValue, text2, "", 
                        subjectDN, Convert.ToBase64String(_signerCert), text, _signId, _referenceId, _signTimeId);
    			}
    			else
    			{
    				foreach (string item2 in _referencesId)
    				{
    					string text3 = item2;
    					if (item2[0] == '#')
    					{
    						text3 = item2.Substring(1);
    					}
    					string xpath = $"//*[@id='{text3}']";
    					XmlElement xmlElement2 = (XmlElement)_doc.SelectSingleNode(xpath);
    					if (xmlElement2 == null)
    					{
    						xpath = $"//*[@Id='{text3}']";
    						xmlElement2 = (XmlElement)_doc.SelectSingleNode(xpath);
    					}
    					if (xmlElement2 == null)
    					{
    						xpath = $"//*[@ID='{text3}']";
    						xmlElement2 = (XmlElement)_doc.SelectSingleNode(xpath);
    					}
    					if (xmlElement2 == null)
    					{
    						xpath = $"//*[@iD='{text3}']";
    						xmlElement2 = (XmlElement)_doc.SelectSingleNode(xpath);
    					}
    					if (xmlElement2 == null)
    					{
    						xmlElement2 = (XmlElement)_doc.SelectSingleNode(text3);
    						if (xmlElement2 != null)
    						{
    							Match match = Regex.Match(text3, "@[Ii][Dd]\\s*=\\s*\"([^\"]+)\"");
    							if (match.Success)
    							{
    								text3 = match.Groups[1].Value;
    							}
    						}
    					}
    					if (xmlElement2 == null)
    					{
    						throw new HashCalculateFailureException("Can not find reference ID " + item2);
    					}
    					text2 = Convert.ToBase64String(DsigSignature.GetC14NDigest(xmlElement2, _doc, alg));
    					list.Add(text2);
    					list2.Add(text3);
    				}
    				signature = DsigSignature.CreateSignature(_hashAlgorithm, _addSigningTime ? _signingTime : DateTime.MinValue, list, "", 
                        subjectDN, Convert.ToBase64String(_signerCert), text, list2, _signId, _signTimeId);
    			}
    			DsigSignature.AddSignatureNode(_doc, signature, _parentNode, _nameSpace, _nameSpaceRef, nguoiKy);
    			byte[] array = null;
    			return _secondHash = DsigSignature.GetHash(_doc, signature, alg);
    		}
    		catch (Exception ex)
    		{
    			throw ex;
    		}
    	}

    	public byte[] Sign(string signedHashBase64)
    	{
    		XmlNodeList elementsByTagName = _doc.GetElementsByTagName("Signature");
    		XmlElement signature = null;
    		foreach (XmlElement item in elementsByTagName)
    		{
    			if (_signId.Equals(item.Attributes["Id"].Value))
    			{
    				signature = item;
    				break;
    			}
    		}
    		DsigSignature.AddSignatureValue(signature, signedHashBase64);
    		Clear();
    		return Encoding.UTF8.GetBytes(_doc.OuterXml.Replace("\r", "&#13;"));
    	}

    	public void SetReferenceId(string id)
    	{
    		if (_referencesId.Count == 0)
    		{
    			_referencesId.Add(id);
    		}
    	}

    	public void SetReferencesId(List<string> ids)
    	{
    		_referencesId = ids;
    	}

    	public void SetSigningTime(DateTime time)
    	{
    		_signingTime = time;
    		_addSigningTime = true;
    	}

    	public void SetSigningTime(DateTime time, string id)
    	{
    		_signingTime = time;
    		_addSigningTime = true;
    		_signTimeId = id;
    	}

    	public void SetParentNodePath(string node)
    	{
    		_parentNode = node;
    	}

    	public void SetNameSpace(string nameSpace, string reference)
    	{
    		_nameSpace = nameSpace;
    		_nameSpaceRef = reference;
    	}

    	public void SetSignatureID(string value)
    	{
    		_signId = value;
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

    	private void Clear()
    	{
    	}

    	public void SetHashAlgorithm(MessageDigestAlgorithm alg)
    	{
    		_hashAlgorithm = alg;
    	}

    	public bool SetSignerCertchain(string pkcs7Base64)
    	{
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

    	public bool CheckHashSignature(byte[] signedBytes)
    	{
    		return CheckHashSignature(Convert.ToBase64String(signedBytes));
    	}

    	public byte[] Sign(byte[] signedBytes)
    	{
    		return Sign(Convert.ToBase64String(signedBytes));
    	}

    	public (byte[] SecondHash, byte[] DataToSigned) PrepareHashBytes()
    	{
    		throw new NotImplementedException();
    	}

    	public byte[] Sign(byte[] tempFileBytes, byte[] signedBytes)
    	{
    		throw new NotImplementedException();
    	}

    	public void SetOcspRespnse(byte[] ocsp)
    	{
    		_ocsp = ocsp;
    	}

    	public void SetCrlResponse(ICollection<byte[]> clrs)
    	{
    		_clrs = clrs;
    	}

    	public bool SetSignerCertchain(ICollection<string> certs)
    	{
    		return true;
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
    		SignerProfile signerProfile = new SignerProfile();
    		signerProfile.DocType = "XML";
    		signerProfile.SecondHashBytes = array;
    		signerProfile.TempData = Encoding.UTF8.GetBytes(_doc.OuterXml.Replace("\r", "&#13;"));
    		signerProfile.Certchain = new byte[1][] { _signerCert };
    		signerProfile.HashAlgorithm = _hashAlgorithm.ToString();
    		signerProfile.Fieldnames = new List<string> { _signId };
    		signerProfile.VersionXML11 = _versionXML11;
    		return signerProfile;
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
    		XmlNodeList elementsByTagName = _doc.GetElementsByTagName("Signature");
    		XmlElement signature = null;
    		foreach (XmlElement item in elementsByTagName)
    		{
    			if (profile.Fieldnames.First().Equals(item.Attributes["Id"]?.Value))
    			{
    				signature = item;
    				break;
    			}
    		}
    		DsigSignature.AddSignatureValue(signature, Convert.ToBase64String(signedBytes));
    		Clear();
    		byte[] bytes = Encoding.UTF8.GetBytes(_doc.OuterXml.Replace("\r", "&#13;"));
    		if (profile.VersionXML11)
    		{
    			bytes[17] = 49;
    		}
    		return bytes;
    	}

    	public bool CheckHashSignature(byte[] hashValue, string signedHashBase64)
    	{
    		byte[] signature = Convert.FromBase64String(signedHashBase64);
    		return new X509Certificate2(_signerCert).GetRSAPublicKey().VerifyHash(hashValue, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    	}

    	public bool CheckHashSignature(SignerProfile profile, byte[] signedBytes)
    	{
    		RSA rSAPublicKey = new X509Certificate2(profile.Certchain.First()).GetRSAPublicKey();
    		HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA256;
    		if (profile.HashAlgorithm.ToLower() == "sha1")
    		{
    			hashAlgorithm = HashAlgorithmName.SHA1;
    		}
    		return rSAPublicKey.VerifyHash(profile.SecondHashBytes, signedBytes, hashAlgorithm, RSASignaturePadding.Pkcs1);
    	}

    	public void EnableTimestamp()
    	{
    		_enableTimestamp = true;
    	}
    }
}
