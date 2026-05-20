using System;
using System.Runtime.Serialization;

namespace SignService.Common.HashSignature.Exceptions
{
    public class CertificateVerificationException : Exception
    {
    	public CertificateVerificationException()
    	{
    	}

    	public CertificateVerificationException(string message)
    		: base(message)
    	{
    	}

    	public CertificateVerificationException(string message, Exception innerException)
    		: base(message, innerException)
    	{
    	}

    	protected CertificateVerificationException(SerializationInfo info, StreamingContext context)
    		: base(info, context)
    	{
    	}
    }
}
