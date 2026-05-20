using System.Collections.Generic;
using SignService.Common.HashSignature.Certificate;
using SignService.Common.HashSignature.Common;

namespace SignService.Common.HashSignature.Interface
{
	public interface IValidator
	{
		List<VerifyResult> Verify(byte[] data, string ocspUrl, string crlUrl, string dateTime, VALIDATE_CERT_OPTION validateOption);

		List<VerifyResult> VerifyCrlBase64(byte[] data, string crlBase64, string ocspUrl = null, string timeCheck = null, VALIDATE_CERT_OPTION validateOption = VALIDATE_CERT_OPTION.USE_OCSP);
	}
}
