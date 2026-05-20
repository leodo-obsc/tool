using System;
using iTextSharp.text.log;
using iTextSharp.text.pdf.security;
using Org.BouncyCastle.Crypto;

namespace SignService.Common.HashSignature.Common
{
    public class TSAClientCeCA : ITSAClient
    {
    	private static readonly ILogger LOGGER = LoggerFactory.GetLogger(typeof(TSAClientBouncyCastle));

    	protected ITSAInfoBouncyCastle tsaInfo;

    	public const int DEFAULTTOKENSIZE = 4096;

    	protected internal int tokenSizeEstimate;

    	public const string DEFAULTHASHALGORITHM = "SHA-256";

    	protected internal string digestAlgorithm;

    	private DateTime _signingTime = DateTime.UtcNow;

    	public void SetTSAInfo(ITSAInfoBouncyCastle tsaInfo)
    	{
    		this.tsaInfo = tsaInfo;
    	}

    	public void SetDateTime(DateTime time)
    	{
    		_signingTime = time;
    	}

    	public IDigest GetMessageDigest()
    	{
    		return DigestAlgorithms.GetMessageDigest(digestAlgorithm);
    	}

    	public byte[] GetTimeStampToken(byte[] imprint)
    	{
    		return null;
    	}

    	public int GetTokenSizeEstimate()
    	{
    		return tokenSizeEstimate;
    	}
    }
}
