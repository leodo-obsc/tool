//extern alias CustomSec; // Định danh cho file Custom của bạn
extern alias gb;    // Định danh cho thư viện chuẩn của Microsoft


using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;
using SignService.Common.HashSignature.Common;
//using System.Security.Cryptography.Xml;

namespace SignService.Common.HashSignature.Xml
{
    public class DsigSignature
    {
    	public enum DsigSignatureMode
    	{
    		Client,
    		Server
    	}

    	public static XmlNode CreateSignature(MessageDigestAlgorithm alg, DateTime signTime, 
            string base64Digest, 
            string base64SignatureValue, 
            string subjectDN, 
            string base64Cert, 
            string rsaKeyValue, 
            string signatureId = "sigid", 
            string referenceUri = "", string signTimeID = "AddSigningTime")
    	{
    		XmlDocument xmlDocument = new XmlDocument();
    		XmlNode xmlNode = xmlDocument.CreateElement("Signature");
    		XmlAttribute xmlAttribute = xmlDocument.CreateAttribute("Id");
    		xmlAttribute.Value = signatureId;
    		xmlNode.Attributes.Append(xmlAttribute);
    		XmlAttribute xmlAttribute2 = xmlDocument.CreateAttribute("xmlns");
    		xmlAttribute2.Value = "http://www.w3.org/2000/09/xmldsig#";
    		xmlNode.Attributes.Append(xmlAttribute2);
    		XmlNode xmlNode2 = xmlNode.AppendChild(xmlDocument.CreateElement("SignedInfo"));
    		XmlNode xmlNode3 = xmlNode2.AppendChild(xmlDocument.CreateElement("CanonicalizationMethod"));
    		XmlAttribute xmlAttribute3 = xmlDocument.CreateAttribute("Algorithm");
    		xmlAttribute3.Value = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    		xmlNode3.Attributes.Append(xmlAttribute3);
    		XmlNode xmlNode4 = xmlNode2.AppendChild(xmlDocument.CreateElement("SignatureMethod"));
            
            //loido: just hard this
            ((XmlElement)xmlNode4).SetAttribute("AlgMethod", "RSA-SHA256");
            XmlAttribute xmlAttribute4 = xmlDocument.CreateAttribute("Algorithm");
    		xmlAttribute4.Value = _getSignatureAlg(alg);
    		xmlNode4.Attributes.Append(xmlAttribute4);
            

            XmlNode xmlNode5 = xmlNode2.AppendChild(xmlDocument.CreateElement("Reference"));
    		XmlAttribute xmlAttribute5 = xmlDocument.CreateAttribute("URI");
    		xmlAttribute5.Value = referenceUri;
    		xmlNode5.Attributes.Append(xmlAttribute5);
    		XmlNode xmlNode6 = xmlNode5.AppendChild(xmlDocument.CreateElement("Transforms")).AppendChild(xmlDocument.CreateElement("Transform"));
    		XmlAttribute xmlAttribute6 = xmlDocument.CreateAttribute("Algorithm");
    		xmlAttribute6.Value = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
    		xmlNode6.Attributes.Append(xmlAttribute6);
    		XmlNode xmlNode7 = xmlNode5.AppendChild(xmlDocument.CreateElement("DigestMethod"));
    		XmlAttribute xmlAttribute7 = xmlDocument.CreateAttribute("Algorithm");
    		xmlAttribute7.Value = _getDigestMethod(alg);
    		xmlNode7.Attributes.Append(xmlAttribute7);
    		xmlNode5.AppendChild(xmlDocument.CreateElement("DigestValue")).InnerText = base64Digest;
    		xmlNode.AppendChild(xmlDocument.CreateElement("SignatureValue")).InnerText = ((base64SignatureValue == null) ? "" : base64SignatureValue);
    		XmlNode xmlNode8 = xmlNode.AppendChild(xmlDocument.CreateElement("KeyInfo"));
            
            //loido:
    		xmlNode8.AppendChild(xmlDocument.CreateElement("KeyValue")).InnerXml = rsaKeyValue;
    		XmlNode xmlNode9 = xmlNode8.AppendChild(xmlDocument.CreateElement("X509Data"));
    		
            //loido:remove 
            xmlNode9.AppendChild(xmlDocument.CreateElement("X509SubjectName")).InnerText = subjectDN;
    		
            xmlNode9.AppendChild(xmlDocument.CreateElement("X509Certificate")).InnerText = base64Cert.Replace("\r", "").Replace("\n", "");
    		if (signTime != DateTime.MinValue)
    		{
                
                //XmlNode parentNode = xmlNode.ParentNode;//lay node cha.
                //XmlNode xmlNode10 = parentNode.InsertAfter(xmlDocument.CreateElement("NguoiKy"), xmlNode);
                //xmlNode10.InnerText = subjectDN;

                //// 3. Chèn nextNode vào ngay PHÍA DƯỚI (phía sau) xmlNode10
                //XmlNode xmlNode11 = parentNode.InsertAfter(xmlDocument.CreateElement("ThoiGianKy"), xmlNode10);
                //xmlNode11.InnerText = signTime.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss");


                XmlNode xmlNode10 = xmlNode.AppendChild(xmlDocument.CreateElement("Object"));
                //Thêm thuộc tính Id cho thẻ<Object> này
                XmlAttribute idAttribute = xmlDocument.CreateAttribute("Id");
                idAttribute.Value = "794ddfe0-022b-4135-adbc-3388fd37b9a3";
                xmlNode10.Attributes.Append(idAttribute);

                XmlAttribute xmlAttribute8 = xmlDocument.CreateAttribute("Id");
                xmlAttribute8.Value = signatureId;
                xmlNode10.Attributes.Append(xmlAttribute8);
                XmlNode xmlNode11 = xmlNode10.AppendChild(xmlDocument.CreateElement("SignatureProperties"));
                XmlAttribute xmlAttribute9 = xmlDocument.CreateAttribute("xmlns");
                xmlAttribute9.Value = "";
                xmlNode11.Attributes.Append(xmlAttribute9);
                XmlAttribute xmlAttribute10 = xmlDocument.CreateAttribute("Id");
                xmlAttribute10.Value = "proid";
                xmlNode11.Attributes.Append(xmlAttribute10);
                XmlNode xmlNode12 = xmlNode11.AppendChild(xmlDocument.CreateElement("SignatureProperty"));
                XmlAttribute xmlAttribute11 = xmlDocument.CreateAttribute("Target");
                xmlAttribute11.Value = "#" + signatureId;
                xmlNode12.Attributes.Append(xmlAttribute11);
                XmlNode xmlNode13 = xmlNode12.AppendChild(xmlDocument.CreateElement("SigningTime"));
                XmlAttribute xmlAttribute12 = xmlDocument.CreateAttribute("xmlns");
                xmlAttribute12.Value = "http://example.org/#signatureProperties";
                xmlNode13.Attributes.Append(xmlAttribute12);
                XmlAttribute xmlAttribute13 = xmlDocument.CreateAttribute("Id");
                xmlAttribute13.Value = signTimeID;
                xmlNode13.Attributes.Append(xmlAttribute13);
                xmlNode13.InnerText = signTime.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss");
            }
    		return xmlDocument.AppendChild(xmlNode);
    	}

    	public static XmlNode CreateSignature(MessageDigestAlgorithm alg, DateTime signTime, 
            List<string> listReference, 
            string base64SignatureValue, 
            string subjectDN, 
            string base64Cert, 
            string rsaKeyValue, 
            List<string> listUri, 
            string signatureId = "sigid", 
            string signTimeID = "AddSigningTime")
    	{
    		XmlDocument xmlDocument = new XmlDocument();
    		XmlNode xmlNode = xmlDocument.CreateElement("Signature");
    		XmlAttribute xmlAttribute = xmlDocument.CreateAttribute("Id");
    		xmlAttribute.Value = signatureId;
    		xmlNode.Attributes.Append(xmlAttribute);
    		XmlAttribute xmlAttribute2 = xmlDocument.CreateAttribute("xmlns");
    		xmlAttribute2.Value = "http://www.w3.org/2000/09/xmldsig#";
    		xmlNode.Attributes.Append(xmlAttribute2);
    		XmlNode xmlNode2 = xmlNode.AppendChild(xmlDocument.CreateElement("SignedInfo"));
    		XmlNode xmlNode3 = xmlNode2.AppendChild(xmlDocument.CreateElement("CanonicalizationMethod"));
    		XmlAttribute xmlAttribute3 = xmlDocument.CreateAttribute("Algorithm");
    		xmlAttribute3.Value = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    		xmlNode3.Attributes.Append(xmlAttribute3);
    		XmlNode xmlNode4 = xmlNode2.AppendChild(xmlDocument.CreateElement("SignatureMethod"));
    		XmlAttribute xmlAttribute4 = xmlDocument.CreateAttribute("Algorithm");
            //loido: just hard this
            ((XmlElement)xmlNode4).SetAttribute("AlgMethod", "RSA-SHA256");

            xmlAttribute4.Value = _getSignatureAlg(alg);
    		xmlNode4.Attributes.Append(xmlAttribute4);
    		for (int i = 0; i < listReference.Count; i++)
    		{
    			XmlNode xmlNode5 = xmlNode2.AppendChild(xmlDocument.CreateElement("Reference"));
    			XmlAttribute xmlAttribute5 = xmlDocument.CreateAttribute("URI");
    			xmlAttribute5.Value = "#" + listUri[i];
    			xmlNode5.Attributes.Append(xmlAttribute5);
    			XmlNode xmlNode6 = xmlNode5.AppendChild(xmlDocument.CreateElement("Transforms")).AppendChild(xmlDocument.CreateElement("Transform"));
    			XmlAttribute xmlAttribute6 = xmlDocument.CreateAttribute("Algorithm");
    			xmlAttribute6.Value = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
    			xmlNode6.Attributes.Append(xmlAttribute6);
    			XmlNode xmlNode7 = xmlNode5.AppendChild(xmlDocument.CreateElement("DigestMethod"));
    			XmlAttribute xmlAttribute7 = xmlDocument.CreateAttribute("Algorithm");
    			xmlAttribute7.Value = _getDigestMethod(alg);
    			xmlNode7.Attributes.Append(xmlAttribute7);
    			xmlNode5.AppendChild(xmlDocument.CreateElement("DigestValue")).InnerText = listReference[i];
    		}

    		xmlNode.AppendChild(xmlDocument.CreateElement("SignatureValue")).InnerText = ((base64SignatureValue == null) ? "" : base64SignatureValue);
    		
            XmlNode xmlNode8 = xmlNode.AppendChild(xmlDocument.CreateElement("KeyInfo"));
            xmlNode8.AppendChild(xmlDocument.CreateElement("KeyValue")).InnerXml = rsaKeyValue; //loido: remove rsaKeyValue

            XmlNode xmlNode9 = xmlNode8.AppendChild(xmlDocument.CreateElement("X509Data"));
    		//loido: remove
            xmlNode9.AppendChild(xmlDocument.CreateElement("X509SubjectName")).InnerText = subjectDN; ////loido: remove subjectDN
            
            xmlNode9.AppendChild(xmlDocument.CreateElement("X509Certificate")).InnerText = base64Cert.Replace("\r", "").Replace("\n", "");
    		if (signTime != DateTime.MinValue)
    		{

                //XmlNode parentNode = xmlNode.ParentNode;//lay node cha.
                //XmlNode xmlNode10 = parentNode.InsertAfter(xmlDocument.CreateElement("NguoiKy"), xmlNode);
                //xmlNode10.InnerText = subjectDN;

                //// 3. Chèn nextNode vào ngay PHÍA DƯỚI (phía sau) xmlNode10
                //XmlNode xmlNode11 = parentNode.InsertAfter(xmlDocument.CreateElement("ThoiGianKy"), xmlNode10);
                //xmlNode11.InnerText = signTime.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss");

                XmlNode xmlNode10 = xmlNode.AppendChild(xmlDocument.CreateElement("Object"));
                XmlAttribute xmlAttribute8 = xmlDocument.CreateAttribute("Id");
                xmlAttribute8.Value = signatureId;
                xmlNode10.Attributes.Append(xmlAttribute8);
                XmlNode xmlNode11 = xmlNode10.AppendChild(xmlDocument.CreateElement("SignatureProperties"));
                XmlAttribute xmlAttribute9 = xmlDocument.CreateAttribute("xmlns");
                xmlAttribute9.Value = "";
                xmlNode11.Attributes.Append(xmlAttribute9);
                XmlAttribute xmlAttribute10 = xmlDocument.CreateAttribute("Id");
                xmlAttribute10.Value = "proid";
                xmlNode11.Attributes.Append(xmlAttribute10);
                XmlNode xmlNode12 = xmlNode11.AppendChild(xmlDocument.CreateElement("SignatureProperty"));
                XmlAttribute xmlAttribute11 = xmlDocument.CreateAttribute("Target");
                xmlAttribute11.Value = "#" + signatureId;
                xmlNode12.Attributes.Append(xmlAttribute11);
                XmlNode xmlNode13 = xmlNode12.AppendChild(xmlDocument.CreateElement("SigningTime"));
                XmlAttribute xmlAttribute12 = xmlDocument.CreateAttribute("xmlns");
                xmlAttribute12.Value = "http://example.org/#signatureProperties";
                xmlNode13.Attributes.Append(xmlAttribute12);
                XmlAttribute xmlAttribute13 = xmlDocument.CreateAttribute("Id");
                xmlAttribute13.Value = signTimeID;
                xmlNode13.Attributes.Append(xmlAttribute13);
                xmlNode13.InnerText = signTime.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss");
            }
    		return xmlDocument.AppendChild(xmlNode);
    	}

    	private static string _getDigestMethod(MessageDigestAlgorithm alg)
    	{
            //return alg switch
            //{
            //	MessageDigestAlgorithm.SHA1 => "http://www.w3.org/2000/09/xmldsig#sha1", 
            //	MessageDigestAlgorithm.SHA256 => "http://www.w3.org/2001/04/xmlenc#sha256", 
            //	MessageDigestAlgorithm.SHA384 => "http://www.w3.org/2001/04/xmldsig-more#sha384", 
            //	MessageDigestAlgorithm.SHA512 => "http://www.w3.org/2001/04/xmlenc#sha512", 
            //	_ => "http://www.w3.org/2001/04/xmlenc#sha256", 
            //};
            switch (alg)
            {
                case MessageDigestAlgorithm.SHA1:
                    return "http://www.w3.org/2000/09/xmldsig#sha1";
                case MessageDigestAlgorithm.SHA256:
                    return "http://www.w3.org/2001/04/xmlenc#sha256";
                case MessageDigestAlgorithm.SHA384:
                    return "http://www.w3.org/2001/04/xmldsig-more#sha384";
                case MessageDigestAlgorithm.SHA512:
                    return "http://www.w3.org/2001/04/xmlenc#sha512";
                default:
                    return "http://www.w3.org/2001/04/xmlenc#sha256";
            }

        }

        private static string _getSignatureAlg(MessageDigestAlgorithm alg)
    	{
            //return alg switch
            //{
            //	MessageDigestAlgorithm.SHA1 => "http://www.w3.org/2000/09/xmldsig#rsa-sha1", 
            //	MessageDigestAlgorithm.SHA256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", 
            //	MessageDigestAlgorithm.SHA384 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", 
            //	MessageDigestAlgorithm.SHA512 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", 
            //	_ => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", 
            //};


            switch (alg)
            {
                case MessageDigestAlgorithm.SHA1:
                    return "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
                case MessageDigestAlgorithm.SHA256:
                    return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
                case MessageDigestAlgorithm.SHA384:
                    return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
                case MessageDigestAlgorithm.SHA512:
                    return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
                default:
                    return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            }

        }

        public static void AddSignatureValue(XmlElement signature, string base64Signed)
    	{
    		XmlNodeList elementsByTagName = signature.GetElementsByTagName("SignatureValue");
    		if (elementsByTagName.Count != 1)
    		{
    			throw new Exception("SignatureValue tag invalid");
    		}
    		elementsByTagName[0].InnerText = base64Signed;
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
    		(((XmlElement)doc.SelectSingleNode(parentNodePath, xmlNamespaceManager)) ?? 
                throw new Exception("No parent node in document. node name=" + parentNodePath)).AppendChild(newChild);
    	}

    	public static bool VerifySignature(byte[] signedDocBytes, string idSignature)
    	{
    		new List<bool>();
    		XmlDocument xmlDocument = new XmlDocument();
    		try
    		{
    			xmlDocument.Load(new MemoryStream(signedDocBytes));
    			var signedXml = new gb::System.Security.Cryptography.Xml.SignedXml(xmlDocument);
    			XmlNodeList elementsByTagName = xmlDocument.GetElementsByTagName("Signature");
    			if (string.IsNullOrEmpty(idSignature))
    			{
    				_ = (XmlElement)elementsByTagName[0];
    			}
    			else
    			{
    				if (idSignature[0] == '#')
    				{
    					idSignature = idSignature.Substring(1);
    				}
    				_ = (XmlElement)elementsByTagName.Cast<XmlNode>().SingleOrDefault((XmlNode node) => node.Attributes["id"].Value == idSignature);
    			}
    			signedXml.LoadXml((XmlElement)elementsByTagName[0]);
    			return signedXml.CheckSignature();
    		}
    		catch (Exception)
    		{
    			return false;
    		}
    	}

    	public static bool VerifySignature(string XmlSignedFilePath, string idSignature)
    	{
    		new List<bool>();
    		XmlDocument xmlDocument = new XmlDocument();
    		try
    		{
    			xmlDocument.Load(XmlSignedFilePath);
    			var signedXml = new gb::System.Security.Cryptography.Xml.SignedXml(xmlDocument);
    			XmlNodeList elementsByTagName = xmlDocument.GetElementsByTagName("Signature");
    			if (string.IsNullOrEmpty(idSignature))
    			{
    				_ = (XmlElement)elementsByTagName[0];
    			}
    			else
    			{
    				if (idSignature[0] == '#')
    				{
    					idSignature = idSignature.Substring(1);
    				}
    				_ = (XmlElement)elementsByTagName.Cast<XmlNode>().SingleOrDefault((XmlNode node) => node.Attributes["id"].Value == idSignature);
    			}
    			signedXml.LoadXml((XmlElement)elementsByTagName[0]);
    			return signedXml.CheckSignature();
    		}
    		catch (Exception)
    		{
    			return false;
    		}
    	}

    	public static byte[] GetHash(XmlDocument xdoc, XmlNode signature, HashAlgorithm alg)
    	{
    		XmlDocument xmlDocument = new XmlDocument();
    		xmlDocument.LoadXml(signature.OuterXml);
    		XmlNodeList elementsByTagName = xmlDocument.GetElementsByTagName("SignedInfo");
    		XmlDocument xmlDocument2 = new XmlDocument();
    		xmlDocument2.LoadXml(elementsByTagName[0].OuterXml);
    		Utils.AddNamespaces(namespaces: Utils.GetPropagatedAttributes(xdoc.DocumentElement), elem: xmlDocument2.DocumentElement);
    		return GetC14NDigest(xmlDocument2, alg);
    	}

    	public static byte[] GetC14NDigest(XmlNode xn, XmlDocument doc, HashAlgorithm alg)
    	{
    		XmlDocument xmlDocument = new XmlDocument();
    		xmlDocument.LoadXml(xn.OuterXml);
    		Utils.AddNamespaces(namespaces: Utils.GetPropagatedAttributes(doc.DocumentElement), elem: xmlDocument.DocumentElement);
    		return GetC14NDigest(xmlDocument, alg);
    	}

    	public static byte[] GetC14NDigest(XmlDocument xdoc, HashAlgorithm alg)
    	{
    		var xmlDsigC14NTransform = new gb::System.Security.Cryptography.Xml.XmlDsigC14NTransform();
    		xmlDsigC14NTransform.LoadInput(xdoc);
    		return xmlDsigC14NTransform.GetDigestedOutput(alg);
    	}
    }
}
