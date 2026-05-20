using SignService.Common.HashSignature.Certificate;
using SignService.Common.HashSignature.Interface;

namespace SignService.Common.HashSignature.Common;

public class VerifyResult
{
	public string signingTime { get; set; }

	public bool signatureStatus { get; set; }

	public CERTIFICATE_STATUS certStatus { get; set; }

	public string certificate { get; set; }

	public int signatureIndex { get; set; }

	public VERIFY_RESULT code { get; set; }

	public string serialNumber { get; set; }

	public string thumbprint { get; set; }

	public string validFrom { get; set; }

	public string validTo { get; set; }

	public string originalData { get; set; }

	public string taxNumber { get; set; }

	public string personalId { get; set; }
}
