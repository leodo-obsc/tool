namespace SignService.Common.HashSignature.Interface;

public enum SIGNING_RESULT
{
	sigSuccess,
	sigBadInput,
	sigBadKey,
	sigSigningFailed,
	sigNotFoundPrvKey,
	sigUnknow,
	sigMultiplePagesNotfound,
	sigPDFPageNumberNotAllow,
	sigXmlNotFoundTagName,
	sigXmlCantRefID,
	sigDataIncludeSigInvalid,
	sigUserCancel,
	sigPDFCantEncryptFile,
	sigInputNull
}
