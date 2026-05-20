using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;

namespace SignService.Common.HashSignature.Certificate
{
    public class CertificateHandle
    {
    	public static ICollection<byte[]> GetClrResponse(List<X509Certificate2> certChain)
    	{
    		ICollection<byte[]> collection = new List<byte[]>();
    		try
    		{
    			foreach (X509Certificate2 item in certChain)
    			{
    				List<string> cRLDistributionPoint = CertExtention.GetCRLDistributionPoint(item);
    				if (cRLDistributionPoint.Count == 0)
    				{
    					throw new Exception("CrlClient.CheckCrl: No CRL url found in certificate.");
    				}
    				string uriString = cRLDistributionPoint[0];
    				byte[] array = new WebClient().DownloadData(new Uri(uriString));
    				if (array != null)
    				{
    					collection.Add(array);
    				}
    			}
    			return collection;
    		}
    		catch (Exception ex)
    		{
    			throw new Exception("CrlClient.CheckCrl: " + ex.Message);
    		}
    	}

    	public static ICollection<byte[]> GetClrResponse(List<Org.BouncyCastle.X509.X509Certificate> certChain)
    	{
    		ICollection<byte[]> collection = new List<byte[]>();
    		try
    		{
    			foreach (Org.BouncyCastle.X509.X509Certificate item in certChain)
    			{
    				try
    				{
    					List<string> cRLDistributionPoint = CertExtention.GetCRLDistributionPoint(item);
    					if (cRLDistributionPoint.Count == 0)
    					{
    						throw new Exception("CrlClient.CheckCrl: No CRL url found in certificate.");
    					}
    					string uriString = cRLDistributionPoint[0];
    					byte[] array = new WebClient().DownloadData(new Uri(uriString));
    					if (array != null)
    					{
    						collection.Add(array);
    					}
    				}
    				catch (Exception)
    				{
    				}
    			}
    			return collection;
    		}
    		catch (Exception ex2)
    		{
    			throw new Exception("CrlClient.CheckCrl: " + ex2.Message);
    		}
    	}

    	public static byte[] GetClrResponse(Org.BouncyCastle.X509.X509Certificate cert)
    	{
    		try
    		{
    			List<string> cRLDistributionPoint = CertExtention.GetCRLDistributionPoint(cert);
    			if (cRLDistributionPoint.Count == 0)
    			{
    				throw new Exception("CrlClient.CheckCrl: No CRL url found in certificate.");
    			}
    			string uriString = cRLDistributionPoint[0];
    			return new WebClient().DownloadData(new Uri(uriString));
    		}
    		catch (Exception innerException)
    		{
    			throw new Exception("CertificateHandle.GetClrResponse fail", innerException);
    		}
    	}

    	public static byte[] GetOcspResponse(List<X509Certificate2> certChain, string ocspUrl = null, DateTime? timeCheck = null)
    	{
    		if (certChain == null || certChain.Count < 2)
    		{
    			throw new Exception("GetOcspResponse: Certchain invalid");
    		}
    		if (certChain[0] == null)
    		{
    			throw new Exception("GetOcspResponse: Not found certificate");
    		}
    		if (certChain[1] == null)
    		{
    			throw new Exception("GetOcspResponse: Not found issuer certificate");
    		}
    		try
    		{
    			string text = null;
    			if (string.IsNullOrEmpty(ocspUrl))
    			{
    				List<string> authorityInformationAccessOcspUrl = CertExtention.GetAuthorityInformationAccessOcspUrl(certChain[0]);
    				if (authorityInformationAccessOcspUrl.Count == 0)
    				{
    					throw new Exception("CertificateHandle.GetOcspResponse: No OCSP url found in certificate");
    				}
    				text = authorityInformationAccessOcspUrl[0];
    			}
    			else
    			{
    				text = ocspUrl;
    			}
    			X509CertificateParser x509CertificateParser = new X509CertificateParser();
    			OcspReq ocspReq = OcspClient.GenerateOcspRequest(serialNumber: x509CertificateParser.ReadCertificate(certChain[0].GetRawCertData()).SerialNumber, issuerCert: x509CertificateParser.ReadCertificate(certChain[1].GetRawCertData()));
    			return OcspClient.PostData(text, ocspReq.GetEncoded(), "application/ocsp-request", "application/ocsp-response");
    		}
    		catch (Exception)
    		{
    			throw;
    		}
    	}

    	public static byte[] GetOcspResponse(Org.BouncyCastle.X509.X509Certificate signer, Org.BouncyCastle.X509.X509Certificate issuer, string ocspUrl = null, DateTime? timeCheck = null)
    	{
    		try
    		{
    			string text = null;
    			if (string.IsNullOrEmpty(ocspUrl))
    			{
    				List<string> authorityInformationAccessOcspUrl = CertExtention.GetAuthorityInformationAccessOcspUrl(signer);
    				if (authorityInformationAccessOcspUrl.Count == 0)
    				{
    					throw new Exception("CertificateHandle.GetOcspResponse: No OCSP url found in certificate");
    				}
    				text = authorityInformationAccessOcspUrl[0];
    			}
    			else
    			{
    				text = ocspUrl;
    			}
    			OcspReq ocspReq = OcspClient.GenerateOcspRequest(issuer, signer.SerialNumber);
    			return OcspClient.PostData(text, ocspReq.GetEncoded(), "application/ocsp-request", "application/ocsp-response");
    		}
    		catch (Exception)
    		{
    			throw;
    		}
    	}

    	public static OcspCertStatus CheckOCSP(List<X509Certificate2> certChain, string ocspUrl = null, DateTime? timeCheck = null)
    	{
    		try
    		{
    			byte[] ocspResponse = GetOcspResponse(certChain, ocspUrl, timeCheck);
    			X509CertificateParser x509CertificateParser = new X509CertificateParser();
    			Org.BouncyCastle.X509.X509Certificate eeCert = x509CertificateParser.ReadCertificate(certChain[0].GetRawCertData());
    			Org.BouncyCastle.X509.X509Certificate issuerCert = x509CertificateParser.ReadCertificate(certChain[1].GetRawCertData());
    			return OcspClient.ProcessOcspResponse(eeCert, issuerCert, ocspResponse, timeCheck);
    		}
    		catch (Exception)
    		{
    			throw;
    		}
    	}
    }
}
