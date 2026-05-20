using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.IO.Packaging;
using SignService.Common.HashSignature.Certificate;
using SignService.Common.HashSignature.Common;
using SignService.Common.HashSignature.Interface;

namespace SignService.Common.HashSignature.Office
{
    public class OfficeValidator : BaseValidator, IValidator
    {
    	private CertificateHandle _certHandle;

    	public OfficeValidator()
    	{
    		if (_certHandle != null)
    		{
    			_certHandle = new CertificateHandle();
    		}
    	}

    	public OfficeValidator(CertificateHandle certHandle)
    	{
    		_certHandle = certHandle;
    	}

    	public List<SignService.Common.HashSignature.Common.VerifyResult> Verify(byte[] data, string ocspUrl, string crlUrl, string dateTime, VALIDATE_CERT_OPTION validateOption)
    	{
    		return VerifyCore(data, null, crlUrl, ocspUrl, dateTime, validateOption);
    	}

    	public List<SignService.Common.HashSignature.Common.VerifyResult> VerifyCrlBase64(byte[] data, string crlBase64, string ocspUrl = null, string timeCheck = null, VALIDATE_CERT_OPTION validateOption = VALIDATE_CERT_OPTION.USE_OCSP)
    	{
    		return VerifyCore(data, crlBase64, null, ocspUrl, timeCheck, validateOption);
    	}

    	private List<SignService.Common.HashSignature.Common.VerifyResult> VerifyCore(byte[] data, string crlBase64, string crlUrl, string ocspUrl = null, string timeCheck = null, VALIDATE_CERT_OPTION validateOption = VALIDATE_CERT_OPTION.USE_OCSP)
    	{
    		List<SignService.Common.HashSignature.Common.VerifyResult> list = new List<SignService.Common.HashSignature.Common.VerifyResult>();
    		if (data == null)
    		{
    			throw new Exception("Signed data is null");
    		}
            using (MemoryStream memoryStream = new MemoryStream())
            {
                Package package = null;
                try
                {
                    memoryStream.Write(data, 0, data.Length);
                    package = Package.Open(memoryStream, FileMode.Open, FileAccess.ReadWrite);
                }
                catch (Exception ex)
                {
                    throw new Exception("Office.VerifyCore: can not open document, " + ex.Message);
                }
                if (package == null)
                {
                    throw new ArgumentException("ValidateSignatures(package)", "package");
                }
                PackageDigitalSignatureManager packageDigitalSignatureManager = new PackageDigitalSignatureManager(package);
                if (!packageDigitalSignatureManager.IsSigned)
                {
                    throw new Exception("Office.VerifyCore: not found signature");
                }
                ReadOnlyCollection<PackageDigitalSignature> signatures = packageDigitalSignatureManager.Signatures;
                if (signatures == null || signatures.Count == 0)
                {
                    throw new Exception("Office.VerifyCore: not found signature");
                }
            
    		    int signatureIndex = 0;
    		    foreach (PackageDigitalSignature item in signatures)
    		    {
    			    SignService.Common.HashSignature.Common.VerifyResult verifyResult = new SignService.Common.HashSignature.Common.VerifyResult();
    			    list.Add(verifyResult);
    			    verifyResult.signatureIndex = signatureIndex;
    			    verifyResult.certStatus = CERTIFICATE_STATUS.UNKNOWN;
    			    item.Verify();
    			    verifyResult.signatureStatus = item.Verify() == System.IO.Packaging.VerifyResult.Success;
    			    verifyResult.signingTime = Utils.ConvertDateToStringTZ(item.SigningTime);
    			    verifyResult.certificate = Convert.ToBase64String(item.Signer.GetRawCertData());
    			    if (!verifyResult.signatureStatus)
    			    {
    				    verifyResult.code = VERIFY_RESULT.vefSigInValid;
    			    }
    			    else if (string.IsNullOrEmpty(verifyResult.certificate))
    			    {
    				    verifyResult.code = VERIFY_RESULT.vefNotFoundCertSigning;
    			    }
    			    else if (_certHandle == null)
    			    {
    				    _certHandle = new CertificateHandle();
    			    }
    		    }
            }
            return list;
    	}
    }
}
