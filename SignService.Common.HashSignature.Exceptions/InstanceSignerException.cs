using System;
using System.Runtime.Serialization;

namespace SignService.Common.HashSignature.Exceptions
{
	public class InstanceSignerException : Exception
	{
		public InstanceSignerException()
		{
		}

		public InstanceSignerException(string message)
			: base(message)
		{
		}

		public InstanceSignerException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

		protected InstanceSignerException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
}
