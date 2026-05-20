using System;
using System.IO;
using System.Net;
using System.Text;
using System.util;
using iTextSharp.text.error_messages;
using iTextSharp.text.log;
using iTextSharp.text.pdf.security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tsp;

namespace SignService.Common.HashSignature.Common
{
	public class TSAClientBouncyCastleRewrite : ITSAClient
	{
		[Serializable]
		public class TSARequest
		{
			public string Request { get; set; }

			public string ClientTime { get; set; }
		}

		[Serializable]
		public class ApiResponse
		{
			public Guid ResponseID { get; set; }

			public string ResponseContent { get; set; }

			public object Content { get; set; }
		}

		private static readonly ILogger LOGGER = LoggerFactory.GetLogger(typeof(TSAClientBouncyCastle));

		protected internal string tsaURL;

		protected internal string tsaUsername;

		protected internal string tsaPassword;

		protected ITSAInfoBouncyCastle tsaInfo;

		public const int DEFAULTTOKENSIZE = 4096;

		protected internal int tokenSizeEstimate;

		public const string DEFAULTHASHALGORITHM = "SHA-256";

		protected internal string digestAlgorithm;

		private DateTime _signingTime = DateTime.Now;

		public TSAClientBouncyCastleRewrite(string url)
			: this(url, null, null, 4096, "SHA-256")
		{
		}

		public TSAClientBouncyCastleRewrite(string url, string username, string password)
			: this(url, username, password, 4096, "SHA-256")
		{
		}

		public TSAClientBouncyCastleRewrite(string url, string username, string password, int tokSzEstimate, string digestAlgorithm)
		{
			tsaURL = url;
			tsaUsername = username;
			tsaPassword = password;
			tokenSizeEstimate = tokSzEstimate;
			this.digestAlgorithm = digestAlgorithm;
		}

		public void SetTSAInfo(ITSAInfoBouncyCastle tsaInfo)
		{
			this.tsaInfo = tsaInfo;
		}

		public void SetDateTime(DateTime time)
		{
			_signingTime = time;
		}

		public virtual int GetTokenSizeEstimate()
		{
			return tokenSizeEstimate;
		}

		public IDigest GetMessageDigest()
		{
			return DigestAlgorithms.GetMessageDigest(digestAlgorithm);
		}

		public virtual byte[] GetTimeStampToken(byte[] imprint)
		{
			TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
			timeStampRequestGenerator.SetCertReq(certReq: true);
			TimeStampRequest timeStampRequest = timeStampRequestGenerator.Generate(nonce: BigInteger.ValueOf(_signingTime.Ticks + Environment.TickCount), digestAlgorithmOid: DigestAlgorithms.GetAllowedDigests(digestAlgorithm), digest: imprint);
			byte[] encoded = timeStampRequest.GetEncoded();
			byte[] resp = ((!tsaURL.Contains("signserver")) ? GetTSAResponse(encoded) : GetTSAResponseBackdate(encoded));
			TimeStampResponse timeStampResponse = new TimeStampResponse(resp);
			timeStampResponse.Validate(timeStampRequest);
			int num = timeStampResponse.GetFailInfo()?.IntValue ?? 0;
			if (num != 0)
			{
				throw new IOException(MessageLocalization.GetComposedMessage("invalid.tsa.1.response.code.2", tsaURL, num));
			}
			TimeStampToken timeStampToken = timeStampResponse.TimeStampToken;
			if (timeStampToken == null)
			{
				throw new IOException(MessageLocalization.GetComposedMessage("tsa.1.failed.to.return.time.stamp.token.2", tsaURL, timeStampResponse.GetStatusString()));
			}
			TimeStampTokenInfo timeStampInfo = timeStampToken.TimeStampInfo;
			byte[] encoded2 = timeStampToken.GetEncoded();
			LOGGER.Info("Timestamp generated: " + timeStampInfo.GenTime.ToString());
			if (tsaInfo != null)
			{
				tsaInfo.InspectTimeStampTokenInfo(timeStampInfo);
			}
			tokenSizeEstimate = encoded2.Length + 32;
			return encoded2;
		}

		protected internal virtual byte[] GetTSAResponseBackdate(byte[] requestBytes)
		{
			return null;
		}

		protected internal virtual byte[] GetTSAResponse1(byte[] requestBytes)
		{
			HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(tsaURL);
			httpWebRequest.ContentLength = requestBytes.Length;
			httpWebRequest.ContentType = "application/timestamp-query";
			httpWebRequest.Method = "POST";
			if (tsaUsername != null && !tsaUsername.Equals(""))
			{
				string s = tsaUsername + ":" + tsaPassword;
				s = Convert.ToBase64String(Encoding.Default.GetBytes(s), Base64FormattingOptions.None);
				httpWebRequest.Headers["Authorization"] = "Basic " + s;
			}
			Stream requestStream = httpWebRequest.GetRequestStream();
			requestStream.Write(requestBytes, 0, requestBytes.Length);
			requestStream.Close();
			HttpWebResponse httpWebResponse = (HttpWebResponse)httpWebRequest.GetResponse();
			if (httpWebResponse.StatusCode != HttpStatusCode.OK)
			{
				throw new IOException(MessageLocalization.GetComposedMessage("invalid.http.response.1", (int)httpWebResponse.StatusCode));
			}
			Stream responseStream = httpWebResponse.GetResponseStream();
			MemoryStream memoryStream = new MemoryStream();
			byte[] array = new byte[1024];
			int count;
			while ((count = responseStream.Read(array, 0, array.Length)) > 0)
			{
				memoryStream.Write(array, 0, count);
			}
			responseStream.Close();
			httpWebResponse.Close();
			byte[] array2 = memoryStream.ToArray();
			string contentEncoding = httpWebResponse.ContentEncoding;
			if (contentEncoding != null && Util.EqualsIgnoreCase(contentEncoding, "base64"))
			{
				array2 = Convert.FromBase64String(Encoding.ASCII.GetString(array2));
			}
			return array2;
		}

		protected internal virtual byte[] GetTSAResponse(byte[] requestBytes)
		{
			HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(tsaURL);
			httpWebRequest.ContentLength = requestBytes.Length;
			httpWebRequest.ContentType = "application/timestamp-query";
			httpWebRequest.Method = "POST";
			if (tsaUsername != null && !tsaUsername.Equals(""))
			{
				string s = tsaUsername + ":" + tsaPassword;
				s = Convert.ToBase64String(Encoding.Default.GetBytes(s));
				httpWebRequest.Headers["Authorization"] = "Basic " + s;
			}
			Stream requestStream = httpWebRequest.GetRequestStream();
			requestStream.Write(requestBytes, 0, requestBytes.Length);
			requestStream.Close();
			HttpWebResponse httpWebResponse = (HttpWebResponse)httpWebRequest.GetResponse();
			if (httpWebResponse.StatusCode != HttpStatusCode.OK)
			{
				throw new IOException("Invalid HTTP response: " + (int)httpWebResponse.StatusCode);
			}
			Stream responseStream = httpWebResponse.GetResponseStream();
			MemoryStream memoryStream = new MemoryStream();
			byte[] array = new byte[1024];
			int num = 0;
			while ((num = responseStream.Read(array, 0, array.Length)) > 0)
			{
				memoryStream.Write(array, 0, num);
			}
			byte[] array2 = memoryStream.ToArray();
			string contentEncoding = httpWebResponse.ContentEncoding;
			if (contentEncoding != null && Util.EqualsIgnoreCase(contentEncoding, "base64"))
			{
				array2 = Convert.FromBase64String(Encoding.ASCII.GetString(array2));
			}
			responseStream.Close();
			httpWebResponse.Close();
			return array2;
		}
	}
}
