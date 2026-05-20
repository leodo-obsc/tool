using System.Collections.Generic;
using SignService.Common.HashSignature.Common;

namespace SignService.Common.HashSignature.Interface
{
    public interface IHashSigner
    {
    	string GetSecondHashAsBase64();

    	byte[] GetSecondHashBytes();

    	SignerProfile GetSignerProfile();

    	bool CheckHashSignature(byte[] signedBytes);

    	bool CheckHashSignature(string signedHashBase64);

    	bool CheckHashSignature(byte[] hashValue, string signedHashBase64);

    	bool CheckHashSignature(SignerProfile profile, byte[] signedBytes);

    	byte[] Sign(string signedHashBase64);

    	byte[] Sign(byte[] signedBytes);

    	byte[] Sign(SignerProfile profile, byte[] signedBytes);

    	void SetHashAlgorithm(MessageDigestAlgorithm alg);

    	void SetOcspRespnse(byte[] ocsp);

    	void SetCrlResponse(ICollection<byte[]> clrs);

    	void EnableLTV(ICollection<byte[]> ocsps, ICollection<byte[]> clrs);

    	void EnableLTV(bool addDocumentLvTimestamp);

    	bool SetSignerCertchain(string pkcs7Base64);

    	bool SetSignerCertchain(ICollection<string> certs);

    	void EnableTimestamp();

    	string GetSignerSubjectDN();
    }
}
