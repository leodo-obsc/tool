using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;

namespace SignService.Common.HashSignature.Cms
{
    public class CmsValidator
    {
    	public static byte[] GetRaw(byte[] input)
    	{
    		return GetSignerInfo(input)?.EncryptedDigest?.GetOctets();
    	}

    	private static SignerInfo GetSignerInfo(byte[] input)
    	{
    		SignerInfo signerInfo = GetSignerInfo(GetSignedData(Asn1Sequence.GetInstance(new Asn1InputStream(input).ReadObject())));
    		if (signerInfo?.UnauthenticatedAttributes != null)
    		{
    			signerInfo = GetSignerInfo(GetSignerInfo(signerInfo));
    		}
    		return signerInfo;
    	}

    	private static SignerInfo GetSignerInfo(SignedData signedData)
    	{
    		Asn1Encodable[] array = signedData?.SignerInfos?.ToArray();
    		if (array != null && array.Length != 0)
    		{
    			return SignerInfo.GetInstance(array[0]);
    		}
    		return null;
    	}

    	private static SignedData GetSignedData(Asn1Sequence sequence)
    	{
    		return SignedData.GetInstance(ContentInfo.GetInstance(sequence).Content);
    	}

    	private static SignedData GetSignerInfo(SignerInfo signerInfo)
    	{
    		Asn1Encodable[] array = signerInfo.UnauthenticatedAttributes.ToArray();
    		for (int i = 0; i < array.Length; i++)
    		{
    			Asn1Sequence instance = Asn1Sequence.GetInstance(array[i]);
    			if (((DerObjectIdentifier)instance[0]).Id == "1.2.840.113549.1.9.16.2.14")
    			{
    				return GetSignedData(Asn1Sequence.GetInstance(Asn1Set.GetInstance(instance[1])[0]));
    			}
    		}
    		return null;
    	}
    }
}
