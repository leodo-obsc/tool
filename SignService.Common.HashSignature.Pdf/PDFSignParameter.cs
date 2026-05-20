using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace SignService.Common.HashSignature.Pdf;

public class PDFSignParameter
{
	[JsonPropertyName("visibleType")]
	public int VisibleType { get; set; }

	[JsonPropertyName("fontSize")]
	public int FontSize { get; set; }

	public string Sigs { get; set; }

	public string Coms { get; set; }

	[JsonPropertyName("fontName")]
	public string FontName { get; set; }

	[JsonPropertyName("fontStyle")]
	public int FontStyle { get; set; }

	[JsonPropertyName("fontColor")]
	public string FontColor { get; set; }

	public string ImageSrc { get; set; }

	public string SignatureText { get; set; }

	[JsonPropertyName("signatures")]
	public IList<PdfSignatureView> Signatures { get; set; }

	[JsonPropertyName("comment")]
	public IList<PdfSignatureComment> Comment { get; set; }
}
