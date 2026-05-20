using System.Text.Json.Serialization;

namespace SignService.Common.HashSignature.Xml
{
	public class XMLSignauterParam
	{
		[JsonPropertyName("namespace")]
		public string Namespace { get; set; }

		[JsonPropertyName("namespaceRef")]
		public string NamespaceRef { get; set; }

		[JsonPropertyName("parentNodePath")]
		public string ParentNodePath { get; set; }

		[JsonPropertyName("referenceId")]
		public string ReferenceId { get; set; }

		[JsonPropertyName("signatureId")]
		public string SignatureId { get; set; }

		[JsonPropertyName("addSigningTimeRef")]
		public bool AddSigningTimeReference { get; set; }
	}
}
