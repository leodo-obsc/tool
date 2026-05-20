namespace SignService.Common.HashSignature.Certificate
{
    public enum CERTIFICATE_STATUS
    {
    	GOOD,
    	UNKNOWN,
    	EXPIRED,
    	NOT_YET_VALID,
    	REVOKED,
    	NOT_KEY_USAGE,
    	CAN_NOT_CHECK_REVOCATION,
    	CERT_NOT_TRUSTED,
    	NOT_FOUND_CERT,
    	NOT_FOUND_ISSUER_CERT,
    	NOT_FOUND_OCSP_URL
    }
}
