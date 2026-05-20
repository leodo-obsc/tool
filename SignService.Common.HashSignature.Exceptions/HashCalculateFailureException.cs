using System;
using System.Runtime.Serialization;

namespace SignService.Common.HashSignature.Exceptions
{
    public class HashCalculateFailureException : Exception
    {
    	public HashCalculateFailureException()
    	{
    	}

    	public HashCalculateFailureException(string message)
    		: base(message)
    	{
    	}

    	public HashCalculateFailureException(string message, Exception innerException)
    		: base(message, innerException)
    	{
    	}

    	protected HashCalculateFailureException(SerializationInfo info, StreamingContext context)
    		: base(info, context)
    	{
    	}
    }
}
