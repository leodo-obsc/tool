using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Packaging;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Org.BouncyCastle.X509;
using SignService.Common.HashSignature.Common;
using SignService.Common.HashSignature.Interface;

namespace SignService.Common.HashSignature.Office
{
	public class OfficeHashSigner : BaseHashSigner, IHashSigner
	{
		private const string RtOfficeDocument = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument";

		private const string OfficeObjectId = "idOfficeObject";

		private const string ManifestHashAlgorithm = "http://www.w3.org/2000/09/xmldsig#sha1";

		private const string DigestMethod_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";

		private PackageDigitalSignatureManager _packageDigitalSignatureManager;

		private Package _package;

		private Org.BouncyCastle.X509.X509Certificate _signer;

		private string _signatureId;

		private MemoryStream _stream = new MemoryStream();

		public MessageDigestAlgorithm DigestAlgrothim { get; set; }

		public OfficeHashSigner()
		{
		}

		public void SetSignerCertificate(string certBase64)
		{
			if (string.IsNullOrEmpty(certBase64))
			{
				return;
			}
			if (certBase64.StartsWith("-----BEGIN CERTIFICATE-----"))
			{
				certBase64 = certBase64.Replace("-----BEGIN CERTIFICATE-----", "").Replace("-----END CERTIFICATE-----", "");
			}
			_signerCert = Convert.FromBase64String(certBase64);
			try
			{
				X509CertificateParser x509CertificateParser = new X509CertificateParser();
				_signer = x509CertificateParser.ReadCertificate(_signerCert);
			}
			catch (Exception)
			{
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

		public OfficeHashSigner(byte[] unsignData, byte[] certBytes)
			: base(unsignData, certBytes)
		{
		}

		public OfficeHashSigner(byte[] unsignData, string certBase64)
			: base(unsignData, certBase64)
		{
		}

		private void Init()
		{
			CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA256SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
			_stream.Write(_unsignData, 0, _unsignData.Length);
			_package = Package.Open(_stream, FileMode.Open, FileAccess.ReadWrite);
			X509Certificate2 certificate = new X509Certificate2(_signerCert);
			List<Uri> list = new List<Uri>();
			List<PackageRelationshipSelector> list2 = new List<PackageRelationshipSelector>();
			foreach (PackageRelationship item in _package.GetRelationshipsByType("http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"))
			{
				AddSignableItems(item, list, list2);
			}
			if (DigestAlgrothim == MessageDigestAlgorithm.SHA256)
			{
				_packageDigitalSignatureManager = new PackageDigitalSignatureManager(_package)
				{
					CertificateOption = CertificateEmbeddingOption.InSignaturePart,
					HashAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256"
				};
			}
			else
			{
				_packageDigitalSignatureManager = new PackageDigitalSignatureManager(_package)
				{
					CertificateOption = CertificateEmbeddingOption.InSignaturePart
				};
			}
			_signatureId = "Signature-" + Guid.NewGuid().GenFlake();
			DataObjectCustom dataObjectCustom = CreateOfficeObject(_signatureId);
			ReferenceCustom referenceCustom = new ReferenceCustom("#idOfficeObject");
			try
			{
				_secondHash = _packageDigitalSignatureManager.HashDataFile(list, certificate, list2, _signatureId, new DataObjectCustom[1] { dataObjectCustom }, new ReferenceCustom[1] { referenceCustom }, (int)DigestAlgrothim);
			}
			catch (Exception)
			{
				throw;
			}
		}

		public bool CheckHashSignature(byte[] hashValue, string signedHashBase64)
		{
			return false;
		}

		public string GetSecondHashAsBase64()
		{
			Init();
			if (_secondHash != null)
			{
				return Convert.ToBase64String(_secondHash);
			}
			return null;
		}

		public byte[] GetSecondHashBytes()
		{
			Init();
			return _secondHash;
		}

		public byte[] Sign(string signedHashBase64)
		{
			try
			{
				byte[] sig = Convert.FromBase64String(signedHashBase64);
				_packageDigitalSignatureManager.SignFile(sig);
				_package.Close();
				_package = null;
				_packageDigitalSignatureManager = null;
				return _stream.ToArray();
			}
			catch (Exception ex)
			{
				ex.LogExceptionToFile();
				throw;
			}
		}

		public bool CheckHashSignature(string signedHashBase64)
		{
			try
			{
				byte[] signature = Convert.FromBase64String(signedHashBase64);
				return new X509Certificate2(_signerCert).GetRSAPublicKey().VerifyHash(_secondHash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
			}
			catch (Exception ex)
			{
				ex.LogExceptionToFile();
				return false;
			}
		}

		public bool CheckHashSignature(byte[] signedBytes)
		{
			return true;
		}

		private void AddSignableItems(PackageRelationship packageRelationship, List<Uri> lstUris, List<PackageRelationshipSelector> lstPackageRelationshipSelectors)
		{
			PackageRelationshipSelector item = new PackageRelationshipSelector(packageRelationship.SourceUri, PackageRelationshipSelectorType.Id, packageRelationship.Id);
			lstPackageRelationshipSelectors.Add(item);
			if (packageRelationship.TargetMode != TargetMode.Internal)
			{
				return;
			}
			PackagePart part = packageRelationship.Package.GetPart(PackUriHelper.ResolvePartUri(packageRelationship.SourceUri, packageRelationship.TargetUri));
			if (lstUris.Contains(part.Uri))
			{
				return;
			}
			lstUris.Add(part.Uri);
			foreach (PackageRelationship relationship in part.GetRelationships())
			{
				AddSignableItems(relationship, lstUris, lstPackageRelationshipSelectors);
			}
		}

		private DataObjectCustom CreateOfficeObject(string signatureId)
		{
			XmlDocument xmlDocument = new XmlDocument();
			XmlDocument xmlDocument2 = new XmlDocument();
			string xml = "<SignatureProperties xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\r\n<SignatureProperty Id=\"idOfficeV1Details\" Target=\"idPackageSignature\">\r\n<SignatureInfoV1 xmlns=\"http://schemas.microsoft.com/office/2006/digsig\">\r\n<ManifestHashAlgorithm>\r\nhttp://www.w3.org/2000/09/xmldsig#sha1\r\n</ManifestHashAlgorithm>\r\n</SignatureInfoV1>\r\n</SignatureProperty>\r\n</SignatureProperties>";
			if (DigestAlgrothim == MessageDigestAlgorithm.SHA256)
			{
				xml = "<SignatureProperties xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\r\n<SignatureProperty Id=\"idOfficeV1Details\" Target=\"idPackageSignature\">\r\n<SignatureInfoV1 xmlns=\"http://schemas.microsoft.com/office/2006/digsig\">\r\n<ManifestHashAlgorithm>\r\nhttp://www.w3.org/2001/04/xmlenc#sha256\r\n</ManifestHashAlgorithm>\r\n</SignatureInfoV1>\r\n</SignatureProperty>\r\n</SignatureProperties>";
			}
			xmlDocument2.LoadXml(xml);
			if (DigestAlgrothim == MessageDigestAlgorithm.SHA256)
			{
				xmlDocument.LoadXml(string.Format(xmlDocument2.OuterXml, signatureId, "http://www.w3.org/2001/04/xmlenc#sha256"));
			}
			else
			{
				xmlDocument.LoadXml(string.Format(xmlDocument2.OuterXml, signatureId, "http://www.w3.org/2000/09/xmldsig#sha1"));
			}
			DataObjectCustom dataObjectCustom = new DataObjectCustom();
			dataObjectCustom.LoadXml(xmlDocument.DocumentElement);
			dataObjectCustom.Id = "idOfficeObject";
			return dataObjectCustom;
		}

		public void SetHashAlgorithm(MessageDigestAlgorithm alg)
		{
			DigestAlgrothim = alg;
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

		public byte[] Sign(byte[] signedBytes)
		{
			try
			{
				_packageDigitalSignatureManager.SignFile(signedBytes);
				_package.Close();
				_package = null;
				_packageDigitalSignatureManager = null;
				return _stream.ToArray();
			}
			catch (Exception)
			{
				throw;
			}
		}

		private byte[] GetTempData()
		{
			try
			{
				_packageDigitalSignatureManager.GetTempData();
				_package.Close();
				_package = null;
				_packageDigitalSignatureManager = null;
				return _stream.ToArray();
			}
			catch (Exception)
			{
				throw;
			}
			finally
			{
				_stream.Close();
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
			try
			{
				Init();
			}
			catch (Exception)
			{
				throw;
			}
			return new SignerProfile
			{
				TempData = GetTempData(),
				SecondHashBytes = _secondHash,
				HashAlgorithm = CryptoConfig.MapNameToOID(DigestAlgrothim.ToString()),
				DocType = "OFFICE",
				Fieldnames = new List<string> { _signatureId }
			};
		}

		public byte[] Sign(SignerProfile profile, byte[] signedBytes)
		{
			MemoryStream memoryStream = new MemoryStream();
			try
			{
				memoryStream.Write(profile.TempData, 0, profile.TempData.Length);
				Package package = Package.Open(memoryStream, FileMode.Open, FileAccess.ReadWrite);
				PackageDigitalSignatureManager packageDigitalSignatureManager = ((!(profile.HashAlgorithm == "2.16.840.1.101.3.4.2.1")) ? new PackageDigitalSignatureManager(package)
				{
					CertificateOption = CertificateEmbeddingOption.InSignaturePart
				} : new PackageDigitalSignatureManager(package)
				{
					CertificateOption = CertificateEmbeddingOption.InSignaturePart,
					HashAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256"
				});
				string fieldName = profile.Fieldnames.First();
				PackageDigitalSignature packageDigitalSignature = packageDigitalSignatureManager.Signatures.Where((PackageDigitalSignature s) => s.Signature?.Id == fieldName).First();
				packageDigitalSignature.Signature.SignatureValue = signedBytes;
				packageDigitalSignature.Sign(signedBytes);
				package.Flush();
				package.Close();
				return memoryStream.ToArray();
			}
			catch (Exception)
			{
				throw;
			}
			finally
			{
				memoryStream.Close();
			}
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
