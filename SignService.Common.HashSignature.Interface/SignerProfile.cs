using System;
using System.Collections.Generic;

namespace SignService.Common.HashSignature.Interface
{
	[Serializable]
	public class SignerProfile
	{
		public string DocType { get; set; }

		public string DocId { get; set; }

		public string DocName { get; set; }

		public string DocFileType { get; set; }

		public string DocMimeType { get; set; }

		public string HashAlgorithm { get; set; }

		public byte[] TempData { get; set; }

		public byte[] DataHashBytes { get; set; }

		public byte[] SecondHashBytes { get; set; }

		public byte[] OwnerPassword { get; set; }

		public bool EnableTimeStamp { get; set; }

		public bool EnableLtv { get; set; }

		public bool LtvTimeStamp { get; set; }

		public string TsaUrl { get; set; }

		public string TsaUsername { get; set; }

		public string TsaPassword { get; set; }

		public DateTime SigTime { get; set; }

		public int EstimatedSize { get; set; }

		public ICollection<string> Fieldnames { get; set; }

		public ICollection<byte[]> Certchain { get; set; }

		public byte[] Ocsp { get; set; }

		public ICollection<byte[]> Clrs { get; set; }

		public bool IsPades { get; set; }

		public bool IsMinIO { get; set; }

		public string MinIoLocation { get; set; }

		public string MinIoBucketname { get; set; }

		public bool VersionXML11 { get; set; }
	}
}
