using System;
using System.Collections;
using System.IO;
using System.Net;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

namespace SignService.Common.HashSignature.Certificate;

public class OcspClient
{
	private static readonly int BufferSize = 32768;

	private readonly int MaxClockSkew = 36000000;

	public static byte[] PostData(string url, byte[] data, string contentType, string accept)
	{
		HttpWebRequest obj = (HttpWebRequest)WebRequest.Create(url);
		obj.Method = "POST";
		obj.ContentType = contentType;
		obj.ContentLength = data.Length;
		obj.Accept = accept;
		Stream requestStream = obj.GetRequestStream();
		requestStream.Write(data, 0, data.Length);
		requestStream.Close();
		Stream responseStream = ((HttpWebResponse)obj.GetResponse()).GetResponseStream();
		byte[] result = ToByteArray(responseStream);
		responseStream.Close();
		return result;
	}

	public static byte[] ToByteArray(Stream stream)
	{
		byte[] array = new byte[BufferSize];
		MemoryStream memoryStream = new MemoryStream();
		int count;
		while ((count = stream.Read(array, 0, array.Length)) > 0)
		{
			memoryStream.Write(array, 0, count);
		}
		return memoryStream.ToArray();
	}

	public static OcspCertStatus ProcessOcspResponse(X509Certificate eeCert, X509Certificate issuerCert, byte[] binaryResp, DateTime? dateTime)
	{
		OcspResp ocspResp = new OcspResp(binaryResp);
		OcspCertStatus result = OcspCertStatus.UNKNOWN;
		if (ocspResp.Status == 0)
		{
			BasicOcspResp basicOcspResp = (BasicOcspResp)ocspResp.GetResponseObject();
			if (basicOcspResp.Responses.Length == 1)
			{
				SingleResp singleResp = basicOcspResp.Responses[0];
				ValidateCertificateId(issuerCert, eeCert, singleResp.GetCertID());
				object certStatus = singleResp.GetCertStatus();
				if (certStatus == CertificateStatus.Good)
				{
					result = OcspCertStatus.GOOD;
				}
				else if (certStatus is RevokedStatus revokedStatus)
				{
					if (dateTime.HasValue)
					{
						DateTime revocationTime = revokedStatus.RevocationTime;
						DateTime? dateTime2 = dateTime;
						result = ((!(revocationTime > dateTime2)) ? OcspCertStatus.REVOKED : OcspCertStatus.GOOD);
					}
					else
					{
						result = OcspCertStatus.REVOKED;
					}
				}
				else if (certStatus is UnknownStatus)
				{
					result = OcspCertStatus.UNKNOWN;
				}
			}
			return result;
		}
		throw new Exception("Unknow status '" + ocspResp.Status + "'.");
	}

	public void ValidateResponse(BasicOcspResp or, X509Certificate issuerCert)
	{
		ValidateResponseSignature(or, issuerCert.GetPublicKey());
		ValidateSignerAuthorization(issuerCert, or.GetCerts()[0]);
	}

	public void ValidateSignerAuthorization(X509Certificate issuerCert, X509Certificate signerCert)
	{
		if (!issuerCert.IssuerDN.Equivalent(signerCert.IssuerDN) || !issuerCert.SerialNumber.Equals(signerCert.SerialNumber))
		{
			throw new Exception("Invalid OCSP signer");
		}
	}

	public void ValidateResponseSignature(BasicOcspResp or, AsymmetricKeyParameter asymmetricKeyParameter)
	{
		if (!or.Verify(asymmetricKeyParameter))
		{
			throw new Exception("Invalid OCSP signature");
		}
	}

	public void ValidateNextUpdate(SingleResp resp)
	{
		if (resp.NextUpdate != null)
		{
			_ = resp.NextUpdate.Value;
			if (resp.NextUpdate.Value.Ticks <= DateTime.Now.Ticks)
			{
				throw new Exception("Invalid next update.");
			}
		}
	}

	public void ValidateThisUpdate(SingleResp resp)
	{
		if (Math.Abs(resp.ThisUpdate.Ticks - DateTime.Now.Ticks) > MaxClockSkew)
		{
			throw new Exception("Max clock skew reached.");
		}
	}

	public static void ValidateCertificateId(X509Certificate issuerCert, X509Certificate eeCert, CertificateID certificateId)
	{
		CertificateID certificateID = new CertificateID("1.3.14.3.2.26", issuerCert, eeCert.SerialNumber);
		if (!certificateID.SerialNumber.Equals(certificateId.SerialNumber))
		{
			throw new Exception("Invalid certificate ID in response");
		}
		if (!Arrays.AreEqual(certificateID.GetIssuerNameHash(), certificateId.GetIssuerNameHash()))
		{
			throw new Exception("Invalid certificate Issuer in response");
		}
	}

	public static OcspReq GenerateOcspRequest(X509Certificate issuerCert, BigInteger serialNumber)
	{
		return GenerateOcspRequest(new CertificateID("1.3.14.3.2.26", issuerCert, serialNumber));
	}

	public static OcspReq GenerateOcspRequest(CertificateID id)
	{
		OcspReqGenerator ocspReqGenerator = new OcspReqGenerator();
		ocspReqGenerator.AddRequest(id);
		BigInteger.ValueOf(default(DateTime).Ticks);
		ArrayList arrayList = new ArrayList();
		Hashtable hashtable = new Hashtable();
		arrayList.Add(OcspObjectIdentifiers.PkixOcsp);
		Asn1OctetString value = new DerOctetString(new DerOctetString(new byte[10] { 1, 3, 6, 1, 5, 5, 7, 48, 1, 1 }));
		hashtable.Add(OcspObjectIdentifiers.PkixOcsp, new X509Extension(critical: false, value));
		ocspReqGenerator.SetRequestExtensions(new X509Extensions(arrayList, hashtable));
		return ocspReqGenerator.Generate();
	}
}
