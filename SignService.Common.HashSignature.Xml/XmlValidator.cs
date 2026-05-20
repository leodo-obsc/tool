using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using SignService.Common.HashSignature.Certificate;
using SignService.Common.HashSignature.Common;
using SignService.Common.HashSignature.Interface;

namespace SignService.Common.HashSignature.Xml
{
    public class XmlValidator : BaseValidator, IValidator
    {
    	private CertificateHandle _certHandle;

    	private const string CERTIFICAT_TAG = "X509Certificate";

    	private const string SIGNINGTIME_ID = "SigningTime";

    	private const string SIGNINGTIME_URI = "signatureProperties";

    	private const string SIGNINGTIME_TAGNAME = "SigningTime";

    	public XmlValidator()
    	{
    		if (_certHandle != null)
    		{
    			_certHandle = new CertificateHandle();
    		}
    	}

    	public XmlValidator(CertificateHandle certHandle)
    	{
    		_certHandle = certHandle;
    	}

    	private List<VerifyResult> VerifyCore(byte[] data, string crlBase64, string crlUrl, string ocspUrl = null, string timeCheck = null, VALIDATE_CERT_OPTION validateOption = VALIDATE_CERT_OPTION.USE_OCSP)
    	{
    		List<VerifyResult> list = new List<VerifyResult>();
    		if (data == null)
    		{
    			throw new Exception("Signed data is null");
    		}
    		XmlDocument xmlDocument = new XmlDocument();
    		xmlDocument.LoadXml(Encoding.UTF8.GetString(data));
    		XmlNodeList elementsByTagName = xmlDocument.GetElementsByTagName("Signature");
    		if (elementsByTagName == null || elementsByTagName.Count == 0)
    		{
    			throw new Exception("Not found siganture");
    		}
    		for (int num = elementsByTagName.Count - 1; num >= 0; num--)
    		{
    			SignedXmlCustom signedXmlCustom = new SignedXmlCustom(xmlDocument);
    			VerifyResult verifyResult = new VerifyResult();
    			list.Add(verifyResult);
    			verifyResult.signatureIndex = num;
    			verifyResult.certStatus = CERTIFICATE_STATUS.UNKNOWN;
    			verifyResult.signingTime = GetSigningTime(elementsByTagName[num]);
    			verifyResult.certificate = GetSignerCert(elementsByTagName[num]);
    			XmlElement xmlElement = (XmlElement)elementsByTagName[num];
    			signedXmlCustom.LoadXml(xmlElement);
    			verifyResult.signatureStatus = signedXmlCustom.CheckSignature();
    			if (!verifyResult.signatureStatus)
    			{
    				verifyResult.code = VERIFY_RESULT.vefSigInValid;
    			}
    			else if (string.IsNullOrEmpty(verifyResult.certificate))
    			{
    				verifyResult.code = VERIFY_RESULT.vefNotFoundCertSigning;
    			}
    			else if (_certHandle != null)
    			{
    				_certHandle = new CertificateHandle();
    			}
    			xmlElement.ParentNode.RemoveChild(xmlElement);
    			xmlDocument.Normalize();
    		}
    		return list;
    	}

    	public static int VerifySignature(byte[] signedData)
    	{
    		if (signedData == null)
    		{
    			return 3;
    		}
    		XmlDocument xmlDocument = new XmlDocument();
    		xmlDocument.LoadXml(Encoding.UTF8.GetString(signedData));
    		SignedXmlCustom signedXmlCustom = new SignedXmlCustom(xmlDocument);
    		XmlNodeList elementsByTagName = xmlDocument.GetElementsByTagName("Signature");
    		if (elementsByTagName == null || elementsByTagName.Count == 0)
    		{
    			return 2;
    		}
    		signedXmlCustom.LoadXml((XmlElement)elementsByTagName[0]);
    		if (signedXmlCustom.CheckSignature())
    		{
    			return 0;
    		}
    		return 1;
    	}

    	public static X509Certificate2 GetCertificate(byte[] data)
    	{
    		if (data == null)
    		{
    			return null;
    		}
    		X509Certificate2 result = null;
    		XmlDocument xmlDocument = new XmlDocument();
    		string text = null;
    		try
    		{
    			xmlDocument.LoadXml(Encoding.Default.GetString(data));
    			XmlNodeList elementsByTagName = xmlDocument.GetElementsByTagName("X509Certificate");
    			if (elementsByTagName.Count == 1)
    			{
    				text = elementsByTagName.Item(0).InnerXml;
    			}
    			if (text != null)
    			{
    				result = new X509Certificate2(Convert.FromBase64String(text));
    			}
    		}
    		catch (Exception)
    		{
    		}
    		return result;
    	}

    	public void AddProperty(XmlElement signaturePropertiesRoot, XmlElement content, XmlDocument doc)
    	{
    		if (content == null)
    		{
    			throw new ArgumentNullException("content");
    		}
    		XmlElement xmlElement = doc.CreateElement("SignatureProperty");
    		xmlElement.SetAttribute("Id", "SigningTime");
    		xmlElement.SetAttribute("Target", "signatureProperties");
    		xmlElement.AppendChild(content);
    		signaturePropertiesRoot.AppendChild(xmlElement);
    	}

    	public string GetSigningTime(XmlNode signature)
    	{
    		XmlDocument xmlDocument = new XmlDocument();
    		xmlDocument.AppendChild(xmlDocument.ImportNode(signature, deep: true));
    		XmlNodeList elementsByTagName = xmlDocument.GetElementsByTagName("SigningTime");
    		if (elementsByTagName != null && elementsByTagName.Count > 0)
    		{
    			return elementsByTagName.Item(0).InnerText;
    		}
    		return null;
    	}

    	public string GetSignerCert(XmlNode signature)
    	{
    		XmlDocument xmlDocument = new XmlDocument();
    		xmlDocument.AppendChild(xmlDocument.ImportNode(signature, deep: true));
    		XmlNodeList elementsByTagName = xmlDocument.GetElementsByTagName("X509Certificate");
    		if (elementsByTagName != null && elementsByTagName.Count > 0)
    		{
    			return elementsByTagName.Item(0).InnerText;
    		}
    		return null;
    	}

    	private static string CheckTimeFormat(string source)
    	{
    		try
    		{
    			string[] array = source.Split(' ');
    			if (array.Length == 2)
    			{
    				string[] array2 = array[0].Split('/');
    				string[] array3 = array[1].Split(':');
    				if (array2.Length == 3 && array3.Length == 3)
    				{
    					int day = int.Parse(array2[0]);
    					int month = int.Parse(array2[1]);
    					int year = int.Parse(array2[2]);
    					int hour = int.Parse(array3[0]);
    					int minute = int.Parse(array3[1]);
    					int second = int.Parse(array3[2]);
    					return new DateTime(year, month, day, hour, minute, second, DateTimeKind.Local).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ssZ", CultureInfo.InvariantCulture);
    				}
    			}
    		}
    		catch (Exception)
    		{
    		}
    		return null;
    	}

    	private static string ConvertTimeToStringTZ(DateTime dt)
    	{
    		try
    		{
    			return dt.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ssZ", CultureInfo.InvariantCulture);
    		}
    		catch (Exception)
    		{
    		}
    		return null;
    	}

    	public List<VerifyResult> Verify(byte[] data, string ocspUrl, string crlUrl, string dateTime, VALIDATE_CERT_OPTION validateOption)
    	{
    		return VerifyCore(data, null, crlUrl, ocspUrl, dateTime, validateOption);
    	}

    	public List<VerifyResult> VerifyCrlBase64(byte[] data, string crlBase64, string ocspUrl = null, string timeCheck = null, VALIDATE_CERT_OPTION validateOption = VALIDATE_CERT_OPTION.USE_OCSP)
    	{
    		return VerifyCore(data, crlBase64, null, ocspUrl, timeCheck, validateOption);
    	}
    }
}
