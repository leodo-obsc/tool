using System.Reflection;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace SignService.Common.HashSignature.Xml
{
	public class RemoteSignedXml : SignedXmlCustom
	{
		private string signatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

		public RemoteSignedXml(XmlDocument xmlDoc)
			: base(xmlDoc)
		{
		}

		public RemoteSignedXml(XmlDocument xmlDoc, string sigMethod)
			: base(xmlDoc)
		{
			signatureMethod = sigMethod;
		}

		public byte[] GetHashValue()
		{
			CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA256SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
			typeof(SignedXmlCustom).GetMethod("BuildDigestedReferences", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(this, null);
			base.SignedInfo.SignatureMethod = signatureMethod;
			HashAlgorithm hashAlgorithm = ((CryptoConfig.CreateFromName(base.SignedInfo.SignatureMethod) as SignatureDescription) ?? throw new CryptographicException("Cryptography_Xml_SignatureDescriptionNotCreated")).CreateDigest();
			if (hashAlgorithm == null)
			{
				throw new CryptographicException("Cryptography_Xml_CreateHashAlgorithmFailed");
			}
			return (byte[])typeof(SignedXmlCustom).GetMethod("GetC14NDigest", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(this, new object[1] { hashAlgorithm });
		}

		public void Sign(byte[] externalSignatureBytes)
		{
			m_signature.SignatureValue = externalSignatureBytes;
		}
	}
}
