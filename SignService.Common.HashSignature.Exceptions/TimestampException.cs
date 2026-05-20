using System;
using System.Runtime.Serialization;

namespace SignService.Common.HashSignature.Exceptions
{
	public class TimestampException : Exception
	{
		public TimestampException()
		{
		}

		public TimestampException(string message)
			: base(message)
		{
		}

		public TimestampException(string message, Exception innerException)
			: base(message, innerException)
		{
		}

		protected TimestampException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
}
