using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using iTextSharp.text;
using iTextSharp.text.error_messages;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;

namespace SignService.Common.HashSignature.Common
{
    public class AdobeLtvEnabling
    {
    	private class ValidationData
    	{
    		public IList<byte[]> crls = new List<byte[]>();

    		public IList<byte[]> ocsps = new List<byte[]>();

    		public IList<byte[]> certs = new List<byte[]>();
    	}

    	private PdfStamper pdfStamper;

    	private ISet<Org.BouncyCastle.X509.X509Certificate> seenCertificates = new HashSet<Org.BouncyCastle.X509.X509Certificate>();

    	private IDictionary<PdfName, ValidationData> validated = new Dictionary<PdfName, ValidationData>();

    	public static List<Org.BouncyCastle.X509.X509Certificate> extraCertificates = new List<Org.BouncyCastle.X509.X509Certificate>();

    	public AdobeLtvEnabling(PdfStamper pdfStamper)
    	{
    		this.pdfStamper = pdfStamper;
    	}

    	public void Enable(IOcspClient ocspClient, ICrlClient crlClient)
    	{
    		AcroFields acroFields = pdfStamper.AcroFields;
    		bool encrypted = pdfStamper.Reader.IsEncrypted();
    		foreach (string signatureName in acroFields.GetSignatureNames())
    		{
    			PdfPKCS7 pdfPKCS = acroFields.VerifySignature(signatureName);
    			PdfDictionary signatureDictionary = acroFields.GetSignatureDictionary(signatureName);
    			Org.BouncyCastle.X509.X509Certificate signingCertificate = pdfPKCS.SigningCertificate;
    			AddLtvForChain(signingCertificate, ocspClient, crlClient, getSignatureHashKey(signatureDictionary, encrypted));
    		}
    		OutputDss();
    	}

    	private void AddLtvForChain(Org.BouncyCastle.X509.X509Certificate certificate, IOcspClient ocspClient, ICrlClient crlClient, PdfName key)
    	{
    		if (seenCertificates.Contains(certificate))
    		{
    			return;
    		}
    		seenCertificates.Add(certificate);
    		ValidationData validationData = new ValidationData();
    		while (certificate != null)
    		{
    			Console.WriteLine(certificate.SubjectDN);
    			Org.BouncyCastle.X509.X509Certificate issuerCertificate = getIssuerCertificate(certificate);
    			validationData.certs.Add(certificate.GetEncoded());
    			byte[] encoded = ocspClient.GetEncoded(certificate, issuerCertificate, null);
    			if (encoded != null)
    			{
    				Console.WriteLine("  with OCSP response");
    				validationData.ocsps.Add(encoded);
    				Org.BouncyCastle.X509.X509Certificate ocspSignerCertificate = getOcspSignerCertificate(encoded);
    				if (ocspSignerCertificate != null)
    				{
    					Console.WriteLine("  signed by {0}\n", ocspSignerCertificate.SubjectDN);
    				}
    				AddLtvForChain(ocspSignerCertificate, ocspClient, crlClient, getOcspHashKey(encoded));
    			}
    			else
    			{
    				ICollection<byte[]> encoded2 = crlClient.GetEncoded(certificate, null);
    				if (encoded2 != null && encoded2.Count > 0)
    				{
    					Console.WriteLine("  with {0} CRLs\n", encoded2.Count);
    					foreach (byte[] item in encoded2)
    					{
    						validationData.crls.Add(item);
    						AddLtvForChain(null, ocspClient, crlClient, getCrlHashKey(item));
    					}
    				}
    			}
    			certificate = issuerCertificate;
    		}
    		validated[key] = validationData;
    	}

    	private void OutputDss()
    	{
    		PdfWriter writer = pdfStamper.Writer;
    		PdfReader reader = pdfStamper.Reader;
    		PdfDictionary pdfDictionary = new PdfDictionary();
    		PdfDictionary pdfDictionary2 = new PdfDictionary();
    		PdfArray pdfArray = new PdfArray();
    		PdfArray pdfArray2 = new PdfArray();
    		PdfArray pdfArray3 = new PdfArray();
    		writer.AddDeveloperExtension(PdfDeveloperExtension.ESIC_1_7_EXTENSIONLEVEL5);
    		writer.AddDeveloperExtension(new PdfDeveloperExtension(PdfName.ADBE, new PdfName("1.7"), 8));
    		PdfDictionary catalog = reader.Catalog;
    		pdfStamper.MarkUsed(catalog);
    		foreach (PdfName key in validated.Keys)
    		{
    			PdfArray pdfArray4 = new PdfArray();
    			PdfArray pdfArray5 = new PdfArray();
    			PdfArray pdfArray6 = new PdfArray();
    			PdfDictionary pdfDictionary3 = new PdfDictionary();
    			foreach (byte[] crl in validated[key].crls)
    			{
    				PdfStream pdfStream = new PdfStream(crl);
    				pdfStream.FlateCompress();
    				PdfIndirectReference indirectReference = writer.AddToBody(pdfStream, inObjStm: false).IndirectReference;
    				pdfArray5.Add(indirectReference);
    				pdfArray2.Add(indirectReference);
    			}
    			foreach (byte[] ocsp in validated[key].ocsps)
    			{
    				PdfStream pdfStream2 = new PdfStream(buildOCSPResponse(ocsp));
    				pdfStream2.FlateCompress();
    				PdfIndirectReference indirectReference2 = writer.AddToBody(pdfStream2, inObjStm: false).IndirectReference;
    				pdfArray4.Add(indirectReference2);
    				pdfArray.Add(indirectReference2);
    			}
    			foreach (byte[] cert in validated[key].certs)
    			{
    				PdfStream pdfStream3 = new PdfStream(cert);
    				pdfStream3.FlateCompress();
    				PdfIndirectReference indirectReference3 = writer.AddToBody(pdfStream3, inObjStm: false).IndirectReference;
    				pdfArray6.Add(indirectReference3);
    				pdfArray3.Add(indirectReference3);
    			}
    			if (pdfArray4.Length > 0)
    			{
    				pdfDictionary3.Put(PdfName.OCSP, writer.AddToBody(pdfArray4, inObjStm: false).IndirectReference);
    			}
    			if (pdfArray5.Length > 0)
    			{
    				pdfDictionary3.Put(PdfName.CRL, writer.AddToBody(pdfArray5, inObjStm: false).IndirectReference);
    			}
    			if (pdfArray6.Length > 0)
    			{
    				pdfDictionary3.Put(PdfName.CERT, writer.AddToBody(pdfArray6, inObjStm: false).IndirectReference);
    			}
    			pdfDictionary3.Put(PdfName.TU, new PdfDate());
    			pdfDictionary2.Put(key, writer.AddToBody(pdfDictionary3, inObjStm: false).IndirectReference);
    		}
    		pdfDictionary.Put(PdfName.VRI, writer.AddToBody(pdfDictionary2, inObjStm: false).IndirectReference);
    		if (pdfArray.Length > 0)
    		{
    			pdfDictionary.Put(PdfName.OCSPS, writer.AddToBody(pdfArray, inObjStm: false).IndirectReference);
    		}
    		if (pdfArray2.Length > 0)
    		{
    			pdfDictionary.Put(PdfName.CRLS, writer.AddToBody(pdfArray2, inObjStm: false).IndirectReference);
    		}
    		if (pdfArray3.Length > 0)
    		{
    			pdfDictionary.Put(PdfName.CERTS, writer.AddToBody(pdfArray3, inObjStm: false).IndirectReference);
    		}
    		catalog.Put(PdfName.DSS, writer.AddToBody(pdfDictionary, inObjStm: false).IndirectReference);
    	}

    	private static PdfName getCrlHashKey(byte[] crlBytes)
    	{
    		return new PdfName(Utilities.ConvertToHex(hashBytesSha1(new DerOctetString(new X509Crl(CertificateList.GetInstance(crlBytes)).GetSignature()).GetEncoded())));
    	}

    	private static PdfName getOcspHashKey(byte[] basicResponseBytes)
    	{
    		return new PdfName(Utilities.ConvertToHex(hashBytesSha1(new DerOctetString(BasicOcspResponse.GetInstance(Asn1Sequence.GetInstance(basicResponseBytes)).Signature.GetBytes()).GetEncoded())));
    	}

    	private static PdfName getSignatureHashKey(PdfDictionary dic, bool encrypted)
    	{
    		byte[] array = dic.GetAsString(PdfName.CONTENTS).GetOriginalBytes();
    		if (PdfName.ETSI_RFC3161.Equals(PdfReader.GetPdfObject(dic.Get(PdfName.SUBFILTER))))
    		{
                using (Asn1InputStream asn1InputStream = new Asn1InputStream(array)) { 
                    array = asn1InputStream.ReadObject().GetEncoded();
                }
            }
    		return new PdfName(Utilities.ConvertToHex(hashBytesSha1(array)));
    	}

    	private static byte[] hashBytesSha1(byte[] b)
    	{
    		return new SHA1CryptoServiceProvider().ComputeHash(b);
    	}

    	private static Org.BouncyCastle.X509.X509Certificate getOcspSignerCertificate(byte[] basicResponseBytes)
    	{
    		BasicOcspResp basicOcspResp = new BasicOcspResp(BasicOcspResponse.GetInstance(Asn1Sequence.GetInstance(basicResponseBytes)));
    		Org.BouncyCastle.X509.X509Certificate[] certs = basicOcspResp.GetCerts();
    		foreach (Org.BouncyCastle.X509.X509Certificate x509Certificate in certs)
    		{
    			if (basicOcspResp.Verify(x509Certificate.GetPublicKey()))
    			{
    				return x509Certificate;
    			}
    		}
    		return null;
    	}

    	private static byte[] buildOCSPResponse(byte[] BasicOCSPResponse)
    	{
    		DerOctetString element = new DerOctetString(BasicOCSPResponse);
    		Asn1EncodableVector asn1EncodableVector = new Asn1EncodableVector();
    		asn1EncodableVector.Add(OcspObjectIdentifiers.PkixOcspBasic);
    		asn1EncodableVector.Add(element);
    		DerEnumerated element2 = new DerEnumerated(0);
    		return new DerSequence(new Asn1EncodableVector
    		{
    			element2,
    			new DerTaggedObject(explicitly: true, 0, new DerSequence(asn1EncodableVector))
    		}).GetEncoded();
    	}

    	private static Org.BouncyCastle.X509.X509Certificate getIssuerCertificate(Org.BouncyCastle.X509.X509Certificate certificate)
    	{
    		string cACURL = getCACURL(certificate);
    		if (cACURL != null && cACURL.Length > 0)
    		{
    			HttpWebResponse httpWebResponse = (HttpWebResponse)((HttpWebRequest)WebRequest.Create(cACURL)).GetResponse();
    			if (httpWebResponse.StatusCode != HttpStatusCode.OK)
    			{
    				throw new IOException(MessageLocalization.GetComposedMessage("invalid.http.response.1", (int)httpWebResponse.StatusCode));
    			}
    			Stream responseStream = httpWebResponse.GetResponseStream();
    			byte[] array = new byte[1024];
    			MemoryStream memoryStream = new MemoryStream();
    			while (true)
    			{
    				int num = responseStream.Read(array, 0, array.Length);
    				if (num <= 0)
    				{
    					break;
    				}
    				memoryStream.Write(array, 0, num);
    			}
    			responseStream.Close();
    			return new Org.BouncyCastle.X509.X509Certificate(X509CertificateStructure.GetInstance(new X509Certificate2(memoryStream.ToArray()).GetRawCertData()));
    		}
    		try
    		{
    			certificate.Verify(certificate.GetPublicKey());
    			return null;
    		}
    		catch (Exception)
    		{
    		}
    		foreach (Org.BouncyCastle.X509.X509Certificate extraCertificate in extraCertificates)
    		{
    			try
    			{
    				certificate.Verify(extraCertificate.GetPublicKey());
    				return extraCertificate;
    			}
    			catch (Exception)
    			{
    			}
    		}
    		return null;
    	}

    	private static string getCACURL(Org.BouncyCastle.X509.X509Certificate certificate)
    	{
    		try
    		{
    			Asn1Object extensionValue = getExtensionValue(certificate, X509Extensions.AuthorityInfoAccess.Id);
    			if (extensionValue == null)
    			{
    				return null;
    			}
    			Asn1Sequence asn1Sequence = (Asn1Sequence)extensionValue;
    			for (int i = 0; i < asn1Sequence.Count; i++)
    			{
    				Asn1Sequence asn1Sequence2 = (Asn1Sequence)asn1Sequence[i];
    				if (asn1Sequence2.Count == 2 && asn1Sequence2[0] is DerObjectIdentifier && ((DerObjectIdentifier)asn1Sequence2[0]).Id.Equals("1.3.6.1.5.5.7.48.2"))
    				{
    					string stringFromGeneralName = getStringFromGeneralName((Asn1Object)asn1Sequence2[1]);
    					return (stringFromGeneralName == null) ? "" : stringFromGeneralName;
    				}
    			}
    		}
    		catch
    		{
    		}
    		return null;
    	}

    	private static Asn1Object getExtensionValue(Org.BouncyCastle.X509.X509Certificate certificate, string oid)
    	{
    		byte[] derEncoded = certificate.GetExtensionValue(new DerObjectIdentifier(oid)).GetDerEncoded();
    		if (derEncoded == null)
    		{
    			return null;
    		}
    		return new Asn1InputStream(new MemoryStream(((Asn1OctetString)new Asn1InputStream(new MemoryStream(derEncoded)).ReadObject()).GetOctets())).ReadObject();
    	}

    	private static string getStringFromGeneralName(Asn1Object names)
    	{
    		Asn1TaggedObject obj = (Asn1TaggedObject)names;
    		return Encoding.GetEncoding(1252).GetString(Asn1OctetString.GetInstance(obj, isExplicit: false).GetOctets());
    	}
    }
}
