using System;
using System.Runtime.Serialization;

namespace SignService.Common.HashSignature.Exceptions
{
    public class LtvEnableFailureException : Exception
    {
    	public LtvEnableFailureException()
    	{
    	}

    	public LtvEnableFailureException(string message)
    		: base(message)
    	{
    	}

    	public LtvEnableFailureException(string message, Exception innerException)
    		: base(message, innerException)
    	{
    	}

    	protected LtvEnableFailureException(SerializationInfo info, StreamingContext context)
    		: base(info, context)
    	{
    	}
    }
}
