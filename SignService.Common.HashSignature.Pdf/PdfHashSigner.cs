using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.util;
using com.itextpdf.text.pdf.security;
using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.parser;
using iTextSharp.text.pdf.security;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using SignService.Common.HashSignature.Certificate;
using SignService.Common.HashSignature.Common;
using SignService.Common.HashSignature.Exceptions;
using SignService.Common.HashSignature.Interface;
using SignService.Common.HashSignature.Properties;

namespace SignService.Common.HashSignature.Pdf;

[Serializable]
public class PdfHashSigner : BaseHashSigner, IHashSigner
{
	public enum RenderMode
	{
		NONE,
		TEXT_ONLY,
		TEXT_WITH_LOGO_LEFT,
		LOGO_ONLY,
		TEXT_WITH_LOGO_TOP,
		TEXT_WITH_BACKGROUND,
		TEXT_WITH_LOGO_BOTTOM
	}

	public enum VisibleSigBorder
	{
		NONE,
		DASHED,
		LINE
	}

	public enum FontName
	{
		Times_New_Roman,
		Roboto,
		Arial
	}

	public enum FontStyle
	{
		Normal,
		Bold,
		Italic,
		BoldItalic,
		Underline
	}

	public enum SignatureStyle
	{
		CMS,
		CADES
	}

	private class MyTextRenderListener : IRenderListener
	{
		private readonly string _text;

		private Rectangle _rect;

		public Rectangle GetRectangle()
		{
			return _rect;
		}

		public string GetRectangleStr()
		{
			return $"{(int)_rect.Left},{(int)_rect.Bottom},{(int)_rect.Right},{(int)_rect.Top}";
		}

		public MyTextRenderListener(string text)
		{
			_text = text;
			_rect = new Rectangle(0f, 0f, 200f, 100f);
		}

		public void BeginTextBlock()
		{
		}

		public void EndTextBlock()
		{
		}

		public void RenderImage(ImageRenderInfo renderInfo)
		{
		}

		public void RenderText(TextRenderInfo renderInfo)
		{
			if (renderInfo.GetText().Equals(_text))
			{
				RectangleJ boundingRectange = renderInfo.GetBaseline().GetBoundingRectange();
				_rect = new Rectangle(boundingRectange.X, boundingRectange.Y - boundingRectange.Height, boundingRectange.X + boundingRectange.Width, boundingRectange.Y);
			}
		}
	}

	private class MyExternalSignatureContainer : IExternalSignatureContainer
	{
		private readonly byte[] signedBytes;

		public MyExternalSignatureContainer(byte[] signedBytes)
		{
			this.signedBytes = signedBytes;
		}

		public byte[] Sign(Stream data)
		{
			return signedBytes;
		}

		public void ModifySigningDictionary(PdfDictionary signDic)
		{
		}
	}

	private byte[] _ownerPassword;

	private PdfReader _reader;

	private PdfStamper _stamper;

	private PdfSignatureAppearance sap;

	private PdfSignature dic;

	private PdfPKCS7 _sgn;

	private ITSAClient _tsa;

	private string _sigFieldNameFrefix;

	private string _signerName = "Me";

	private string _issuerName = "CA";

	private string _reason = "Protect document";

	private string _location = "Location";

	private string _contact = "";

	private Rectangle _rectangle = new Rectangle(0f, 0f, 0f, 0f);

	private int _page = 1;

	private DateTime _dateTimeCreate;

	private Font _font;

	private MemoryStream _outStream;

	private Org.BouncyCastle.X509.X509Certificate _signer;

	private Org.BouncyCastle.X509.X509Certificate[] _certChain;

	private bool _isPades;

	private int _signatureEstimatedSize;

	private byte[] _customImage;

	private readonly string _defaultImage = "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";

	public const int RENDERING_MODE_IMAGE_ONLY = 1;

	public const int RENDERING_MODE_IMAGE_AND_DESCRIPTION = 2;

	public const int RENDERING_MODE_DESCRIPTION_ONLY = 3;

	private RenderMode _renderMode;

	private VisibleSigBorder _borderType;

	private string _layer2Text;

	private FontName _fontName = FontName.Roboto;

	private int _fontSize = 10;

	private FontStyle _fontStyle;

	private int _r;

	private int _g;

	private int _b;

	private bool _isVisibleAllPages;

	private List<PdfSignatureComment> _comments;

	private List<PdfSignatureView> _signatureViews;

	private byte[] tempData;

	private string _author;

	public string FileName { get; set; }

	public PdfHashSigner()
	{
	}

	public PdfHashSigner(byte[] unsignData, byte[] certBytes)
		: base(unsignData, certBytes)
	{
		try
		{
			X509CertificateParser x509CertificateParser = new X509CertificateParser();
			_signer = x509CertificateParser.ReadCertificate(certBytes);
		}
		catch (Exception innerException)
		{
			throw new InstanceSignerException("Signer certificate malformed format", innerException);
		}
		try
		{
			if (_signer.GetSubjectAlternativeNames() != null)
			{
				foreach (IList subjectAlternativeName in _signer.GetSubjectAlternativeNames())
				{
					if ((subjectAlternativeName[1]?.ToString() ?? "").Contains("@"))
					{
						_contact = subjectAlternativeName[1]?.ToString() ?? "";
						break;
					}
				}
			}
			_certChain = new Org.BouncyCastle.X509.X509Certificate[1] { _signer };
		}
		catch (Exception ex)
		{
			ex.LogExceptionToFile();
		}
		Init();
	}

	public PdfHashSigner(byte[] unsignData, string certBase64)
		: base(unsignData, certBase64)
	{
		try
		{
			X509CertificateParser x509CertificateParser = new X509CertificateParser();
			_signer = x509CertificateParser.ReadCertificate(Convert.FromBase64String(certBase64));
		}
		catch (Exception innerException)
		{
			throw new InstanceSignerException("Signer certificate malformed format", innerException);
		}
		try
		{
			if (_signer.GetSubjectAlternativeNames() != null)
			{
				foreach (IList subjectAlternativeName in _signer.GetSubjectAlternativeNames())
				{
					if ((subjectAlternativeName[1]?.ToString() ?? "").Contains("@"))
					{
						_contact = subjectAlternativeName[1]?.ToString() ?? "";
						break;
					}
				}
			}
			_certChain = new Org.BouncyCastle.X509.X509Certificate[1] { _signer };
		}
		catch (Exception ex)
		{
			ex.LogExceptionToFile();
		}
		Init();
	}

	public PdfHashSigner(byte[] unsignData, string certBase64, string tsaUrl, string tsaUsername, string tsaPassword)
		: base(unsignData, certBase64, tsaUrl, tsaUsername, tsaPassword)
	{
		try
		{
			X509CertificateParser x509CertificateParser = new X509CertificateParser();
			_signer = x509CertificateParser.ReadCertificate(Convert.FromBase64String(certBase64));
		}
		catch (Exception innerException)
		{
			throw new InstanceSignerException("Signer certificate malformed format", innerException);
		}
		try
		{
			ICollection subjectAlternativeNames = _signer.GetSubjectAlternativeNames();
			if (subjectAlternativeNames != null)
			{
				foreach (IList item in subjectAlternativeNames)
				{
					if ((item[1]?.ToString() ?? "").Contains("@"))
					{
						_contact = item[1]?.ToString() ?? "";
						break;
					}
				}
			}
			_certChain = new Org.BouncyCastle.X509.X509Certificate[1] { _signer };
			Init();
		}
		catch (Exception ex)
		{
			ex.LogExceptionToFile();
			throw new InstanceSignerException("Parse signer name failed from subject alternative", ex);
		}
	}

	public PdfHashSigner(byte[] unsignData, System.Security.Cryptography.X509Certificates.X509Certificate signerCert, string tsaUrl, string tsaUsername, string tsaPassword)
		: base(unsignData, signerCert, tsaUrl, tsaUsername, tsaPassword)
	{
		try
		{
			X509CertificateParser x509CertificateParser = new X509CertificateParser();
			_signer = x509CertificateParser.ReadCertificate(signerCert.GetRawCertData());
		}
		catch (Exception innerException)
		{
			throw new InstanceSignerException("Signer certificate malformed format", innerException);
		}
		try
		{
			ICollection subjectAlternativeNames = _signer.GetSubjectAlternativeNames();
			if (subjectAlternativeNames != null)
			{
				foreach (IList item in subjectAlternativeNames)
				{
					if ((item[1]?.ToString() ?? "").Contains("@"))
					{
						_contact = item[1]?.ToString() ?? "";
						break;
					}
				}
			}
			_certChain = new Org.BouncyCastle.X509.X509Certificate[1] { _signer };
			Init();
		}
		catch (Exception ex)
		{
			ex.LogExceptionToFile();
			throw new InstanceSignerException("Parse signer name failed from subject alternative", ex);
		}
	}

	public PdfHashSigner(byte[] unsignData, string certBase64, string certChain, string tsaUrl, string tsaUsername, string tsaPassword)
		: base(unsignData, certBase64, tsaUrl, tsaUsername, tsaPassword)
	{
		try
		{
			X509CertificateParser x509CertificateParser = new X509CertificateParser();
			_signer = x509CertificateParser.ReadCertificate(Convert.FromBase64String(certBase64));
		}
		catch (Exception innerException)
		{
			throw new InstanceSignerException("Signer certificate malformed format", innerException);
		}
		try
		{
			PemReader pemReader = new PemReader(new StringReader(certChain));
			object obj = null;
			List<Org.BouncyCastle.X509.X509Certificate> list = new List<Org.BouncyCastle.X509.X509Certificate>();
			while ((obj = pemReader.ReadObject()) != null)
			{
				if (obj.GetType() == typeof(Org.BouncyCastle.X509.X509Certificate))
				{
					Org.BouncyCastle.X509.X509Certificate item = (Org.BouncyCastle.X509.X509Certificate)obj;
					list.Add(item);
				}
			}
			_certChain = list.ToArray();
		}
		catch (Exception innerException2)
		{
			throw new InstanceSignerException("certChain invalid", innerException2);
		}
		if (_certChain.Length < 1)
		{
			_certChain = new Org.BouncyCastle.X509.X509Certificate[1] { _signer };
		}
		try
		{
			ICollection subjectAlternativeNames = _signer.GetSubjectAlternativeNames();
			if (subjectAlternativeNames != null)
			{
				foreach (IList item2 in subjectAlternativeNames)
				{
					if ((item2[1]?.ToString() ?? "").Contains("@"))
					{
						_contact = item2[1]?.ToString() ?? "";
						break;
					}
				}
			}
			Init();
		}
		catch (Exception ex)
		{
			ex.LogExceptionToFile();
			throw new InstanceSignerException("Init signer failed", ex);
		}
	}

	private void Init()
	{
		try
		{
			Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
		}
		catch (Exception)
		{
		}
		_signerName = "Signer";
		_issuerName = "Issuer";
		try
		{
			IList valueList = _signer.SubjectDN.GetValueList(CertificateInfo.X509Name.CN);
			if (valueList != null && valueList.Count > 0)
			{
				_signerName = valueList[0]?.ToString() ?? "";
			}
			valueList = _signer.IssuerDN.GetValueList(CertificateInfo.X509Name.CN);
			if (valueList != null && valueList.Count > 0)
			{
				_issuerName = valueList[0]?.ToString() ?? "";
			}
		}
		catch (Exception)
		{
			throw;
		}
		if (_customImage == null)
		{
			try
			{
				_customImage = Convert.FromBase64String(_defaultImage);
			}
			catch (Exception)
			{
				throw;
			}
		}
		_dateTimeCreate = DateTime.Now;
		_author = _signerName;
	}

	public void SetSignerCertificate(string certBase64)
	{
		if (string.IsNullOrEmpty(certBase64))
		{
			LogFile.LogToFile("PdfHashSigner.SetSignerCertificate(): certBase64 null");
			return;
		}
		if (certBase64.StartsWith("-----BEGIN CERTIFICATE-----"))
		{
			certBase64 = certBase64.Replace("-----BEGIN CERTIFICATE-----", "").Replace("-----END CERTIFICATE-----", "");
		}
		try
		{
			_signerCert = Convert.FromBase64String(certBase64);
			X509CertificateParser x509CertificateParser = new X509CertificateParser();
			_signer = x509CertificateParser.ReadCertificate(Convert.FromBase64String(certBase64));
			if (_signer.GetSubjectAlternativeNames() != null)
			{
				foreach (IList subjectAlternativeName in _signer.GetSubjectAlternativeNames())
				{
					if ((subjectAlternativeName[1]?.ToString() ?? "").Contains("@"))
					{
						_contact = subjectAlternativeName[1]?.ToString() ?? "";
						break;
					}
				}
			}
			_certChain = new Org.BouncyCastle.X509.X509Certificate[1] { _signer };
			Init();
		}
		catch (Exception)
		{
			throw;
		}
	}

	public bool SetSignerCertChain(string caX509, string rootX509)
	{
		X509CertificateParser x509CertificateParser = new X509CertificateParser();
		try
		{
			Org.BouncyCastle.X509.X509Certificate x509Certificate = x509CertificateParser.ReadCertificate(Convert.FromBase64String(caX509));
			Org.BouncyCastle.X509.X509Certificate x509Certificate2 = x509CertificateParser.ReadCertificate(Convert.FromBase64String(rootX509));
			_certChain = new Org.BouncyCastle.X509.X509Certificate[3];
			_certChain[0] = _signer;
			_certChain[1] = x509Certificate;
			_certChain[2] = x509Certificate2;
			return true;
		}
		catch (Exception ex)
		{
			throw new CertificateVerificationException(ex.Message, ex);
		}
	}

	public bool SetSignerCertchain(string pkcs7Base64)
	{
		if (string.IsNullOrEmpty(pkcs7Base64))
		{
			LogFile.LogToFile("PdfHashSigner.SetSignerCertchain(): pkcs7Base64 null");
			throw new CertificateVerificationException("Input must not be null");
		}
		if (pkcs7Base64.StartsWith("-----BEGIN PKCS7-----"))
		{
			pkcs7Base64 = pkcs7Base64.Replace("-----BEGIN PKCS7-----", "").Replace("-----END PKCS7-----", "").Replace("\n", "")
				.Replace("\r", "");
		}
		try
		{
			ArrayList arrayList = new ArrayList(new CmsSignedData(Convert.FromBase64String(pkcs7Base64)).GetCertificates("Collection").GetMatches(null));
			Org.BouncyCastle.X509.X509Certificate x509Certificate = (Org.BouncyCastle.X509.X509Certificate)arrayList[0];
			if (x509Certificate.GetIssuerAlternativeNames() != null)
			{
				foreach (object subjectAlternativeName in x509Certificate.GetSubjectAlternativeNames())
				{
					try
					{
						ArrayList arrayList2 = (ArrayList)subjectAlternativeName;
						_ = $"{arrayList2[1]}";
					}
					catch (Exception)
					{
					}
				}
			}
			List<Org.BouncyCastle.X509.X509Certificate> list = new List<Org.BouncyCastle.X509.X509Certificate>();
			foreach (object item in arrayList)
			{
				list.Add((Org.BouncyCastle.X509.X509Certificate)item);
			}
			_certChain = list.ToArray();
			if (!_certChain[0].SubjectDN.Equals(_signer.SubjectDN))
			{
				Array.Reverse(_certChain);
			}
			_contact = "";
			if (_signer.GetSubjectAlternativeNames() != null)
			{
				foreach (IList subjectAlternativeName2 in _signer.GetSubjectAlternativeNames())
				{
					if ((subjectAlternativeName2[1]?.ToString() ?? "").Contains("@"))
					{
						_contact = subjectAlternativeName2[1]?.ToString() ?? "";
						break;
					}
				}
			}
			_signerCert = _signer.GetEncoded();
			Init();
			return true;
		}
		catch (Exception innerException)
		{
			throw new CertificateVerificationException("Invalid input", innerException);
		}
	}

	public void SetUnsignData(string base64Data)
	{
		_unsignData = Convert.FromBase64String(base64Data);
	}

	private static int CalculateEstimatedSignatureSize(Org.BouncyCastle.X509.X509Certificate[] certChain, ITSAClient tsc, byte[] ocsp, ICollection<byte[]> crlList)
	{
		int num = 0;
		if (certChain != null)
		{
			foreach (Org.BouncyCastle.X509.X509Certificate x509Certificate in certChain)
			{
				num += ((x509Certificate != null) ? x509Certificate.GetEncoded().Length : 0);
			}
		}
		num += 2000;
		if (ocsp != null)
		{
			num += ocsp.Length;
		}
		if (tsc != null)
		{
			num += 4096;
		}
		if (crlList != null)
		{
			foreach (byte[] crl in crlList)
			{
				num += ((crl != null) ? crl.Length : 0);
			}
			num += 100;
		}
		return num;
	}

	private void CalculateSignature()
	{
		try
		{
			_outStream = new MemoryStream();
			_sgn = new PdfPKCS7(null, _certChain, HASH_ALGORITHM, hasRSAdata: false);
			try
			{
				if (_ownerPassword != null)
				{
					_reader = new PdfReader(_unsignData, _ownerPassword);
				}
				else
				{
					_reader = new PdfReader(_unsignData);
				}
				_stamper = PdfStamper.CreateSignature(_reader, _outStream, '\0', null, append: true);
			}
			catch (Exception ex)
			{
				if (_ownerPassword != null)
				{
					_reader = new PdfReader(_unsignData, _ownerPassword);
				}
				else
				{
					_reader = new PdfReader(_unsignData);
				}
				_stamper = PdfStamper.CreateSignature(_reader, _outStream, '\0', null, append: false);
				ex.LogExceptionToFile();
				throw new HashCalculateFailureException(ex.Message, ex);
			}
			sap = _stamper.SignatureAppearance;
			sap.Contact = _contact;
			sap.Layer2Font = CalculateFont(_fontName, _fontSize, (int)_fontStyle, _r, _g, _b);
			sap.IsVisibleAllPages = _isVisibleAllPages;
			if (string.IsNullOrEmpty(_layer2Text))
			{
				_layer2Text = "Ký bởi: " + _signerName + "\nNgày ký: " + _dateTimeCreate.ToString("dd/MM/yyyy HH:mm:ss");
			}
			sap.Layer2Text = _layer2Text;
			sap.SignDate = _dateTimeCreate;
			sap.Reason = _reason;
			sap.Location = _location;
			sap.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.GRAPHIC;
			_sigFieldNameFrefix = CalculateSignatureFieldName(_reader, "SCA");
			sap.SetVisibleSignature(_rectangle, _page, _sigFieldNameFrefix);
			PdfName subFilter = ((!_isPades) ? PdfName.ADBE_PKCS7_DETACHED : PdfName.ETSI_CADES_DETACHED);
			dic = new PdfSignature(PdfName.ADOBE_PPKLITE, subFilter)
			{
				Date = new PdfDate(_dateTimeCreate),
				Name = _signerName,
				Reason = sap.Reason,
				Location = sap.Location,
				Contact = sap.Contact,
				SignatureCreator = string.Empty
			};
			sap.CryptoDictionary = dic;
			try
			{
				if (_customImage == null || _customImage.Length < 1)
				{
					_customImage = Convert.FromBase64String(_defaultImage);
				}
				sap.Image = Image.GetInstance(_customImage);
			}
			catch (Exception)
			{
				throw;
			}
			new Phrase(_layer2Text, _font);
			new PdfPTable(1).WidthPercentage = 100f;
			if (_signatureViews == null || _signatureViews.Count < 1)
			{
				_signatureViews = new List<PdfSignatureView>
				{
					new PdfSignatureView
					{
						Page = 1,
						Rectangle = "5,5,165,85"
					}
				};
			}
			if (_signatureViews != null && _signatureViews.Count > 0)
			{
				List<PdfSignatureAppearance.SignatureView> list = new List<PdfSignatureAppearance.SignatureView>();
				foreach (PdfSignatureView signatureView in _signatureViews)
				{
					signatureView.Id = CalculateSignatureFieldName(_reader, "SM");
					list.Add(new PdfSignatureAppearance.SignatureView
					{
						FieldName = signatureView.Id,
						Page = signatureView.Page,
						Rectangle = signatureView.Rectangle
					});
				}
				sap.Signatures = list;
			}
			if (_comments != null)
			{
				foreach (PdfSignatureComment comment in _comments)
				{
					AddAnnotation(comment);
				}
			}
			PdfSignatureAppearance pdfSignatureAppearance = sap;
			pdfSignatureAppearance.VisibleType = _renderMode switch
			{
				RenderMode.TEXT_ONLY => PdfSignatureAppearance.RenderMode.TEXT_ONLY, 
				RenderMode.LOGO_ONLY => PdfSignatureAppearance.RenderMode.LOGO_ONLY, 
				RenderMode.TEXT_WITH_LOGO_LEFT => PdfSignatureAppearance.RenderMode.TEXT_WITH_LOGO_LEFT, 
				RenderMode.TEXT_WITH_LOGO_TOP => PdfSignatureAppearance.RenderMode.TEXT_WITH_LOGO_TOP, 
				RenderMode.TEXT_WITH_BACKGROUND => PdfSignatureAppearance.RenderMode.TEXT_WITH_BACKGROUND, 
				RenderMode.TEXT_WITH_LOGO_BOTTOM => PdfSignatureAppearance.RenderMode.TEXT_WITH_LOGO_BOTTOM, 
				RenderMode.NONE => PdfSignatureAppearance.RenderMode.NONE, 
				_ => PdfSignatureAppearance.RenderMode.TEXT_WITH_BACKGROUND, 
			};
			CalculateVisibleSignatureBorder(sap, _borderType);
			if (!string.IsNullOrEmpty(_tsaUrl) && _enableTimestamp)
			{
				_tsa = new TSAClientBouncyCastleRewrite(_tsaUrl, _tsaUsername, _tsaPassword, 4096, "SHA-1");
				((TSAClientBouncyCastleRewrite)_tsa).SetDateTime(_dateTimeCreate);
			}
			_signatureEstimatedSize = CalculateEstimatedSignatureSize(_certChain, _tsa, _ocsp, _clrs);
			IExternalSignatureContainer externalSignatureContainer = new ExternalBlankSignatureContainer(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
			MakeSignature.SignExternalContainer(sap, externalSignatureContainer, _signatureEstimatedSize);
			tempData = _outStream.ToArray();
			IDigest digest = DigestUtilities.GetDigest(HASH_ALGORITHM);
			Stream rangeStream = sap.GetRangeStream();
			byte[] array = new byte[8192];
			int length;
			while ((length = rangeStream.Read(array, 0, array.Length)) > 0)
			{
				digest.BlockUpdate(array, 0, length);
			}
			_hashOnlyBytes = new byte[digest.GetDigestSize()];
			digest.DoFinal(_hashOnlyBytes, 0);
			PdfPKCS7 pdfPKCS = new PdfPKCS7(null, _certChain, HASH_ALGORITHM, hasRSAdata: false);
			CryptoStandard sigtype = (_isPades ? CryptoStandard.CADES : CryptoStandard.CMS);
			_signerInfoData = pdfPKCS.getAuthenticatedAttributeBytes(_hashOnlyBytes, _ocsp, _clrs, sigtype);
			_reader.Close();
			_stamper.Close();
		}
		catch (Exception ex3)
		{
			ex3.LogExceptionToFile();
			Clear();
			throw new HashCalculateFailureException(ex3.Message, ex3);
		}
	}

	public bool CheckHashSignature(byte[] hashValue, string signedHashBase64)
	{
		return false;
	}

	public byte[] GetTempPdf()
	{
		return tempData;
	}

	public string CalculateRectangle(string text, float width, float height, float marginTop)
	{
		using PdfReader pdfReader = new PdfReader(_unsignData);
		MyTextRenderListener myTextRenderListener = new MyTextRenderListener(text);
		PdfContentStreamProcessor pdfContentStreamProcessor = new PdfContentStreamProcessor(myTextRenderListener);
		for (int i = 1; i <= pdfReader.NumberOfPages; i++)
		{
			PdfDictionary asDict = pdfReader.GetPageN(i).GetAsDict(PdfName.RESOURCES);
			pdfContentStreamProcessor.ProcessContent(ContentByteUtils.GetContentBytesForPage(pdfReader, i), asDict);
		}
		Rectangle rectangle = myTextRenderListener.GetRectangle();
		rectangle.Left += (float)(((double)rectangle.Width - (double)width) / 2.0);
		Rectangle rectangle2 = new Rectangle(rectangle.Left, rectangle.Bottom - height - marginTop, rectangle.Left + width, rectangle.Bottom - marginTop);
		return $"{(int)rectangle2.Left},{(int)rectangle2.Bottom},{(int)rectangle2.Right},{(int)rectangle2.Top}";
	}

	private PdfTemplate NormalizeTemplate(PdfTemplate frm1, int p, Rectangle rect, string name)
	{
		int pageRotation = _reader.GetPageRotation(p);
		Rectangle rectangle = new Rectangle(rect.Width, rect.Height);
		for (int num = pageRotation; num > 0; num -= 90)
		{
			rectangle = rectangle.Rotate();
		}
		PdfTemplate pdfTemplate = PdfTemplate.CreateTemplate(_stamper.Writer, 10f, 10f);
		pdfTemplate.BoundingBox = rectangle;
		switch (pageRotation)
		{
		case 90:
			pdfTemplate.ConcatCTM(0f, 1f, -1f, 0f, rect.Height, 0f);
			break;
		case 180:
			pdfTemplate.ConcatCTM(-1f, 0f, 0f, -1f, rect.Width, rect.Height);
			break;
		case 270:
			pdfTemplate.ConcatCTM(0f, -1f, 1f, 0f, 0f, rect.Width);
			break;
		}
		pdfTemplate.AddTemplate(frm1, 0f, 0f);
		PdfTemplate pdfTemplate2 = PdfTemplate.CreateTemplate(_stamper.Writer, 10f, 10f);
		pdfTemplate2.BoundingBox = rectangle;
		pdfTemplate2.AddTemplate(pdfTemplate, 0f, 0f);
		return pdfTemplate2;
	}

	private void AddAnnotation(PdfSignatureComment comment)
	{
		if (comment != null && comment.GetRectangle() != null)
		{
			switch (comment.Type)
			{
			case 1:
				AddImageAnnotation(comment);
				break;
			case 2:
				AddTextAnnotation(comment);
				break;
			case 3:
				AddSignatureAnnotation(comment);
				break;
			}
		}
	}

	private void AddSignatureAnnotation(PdfSignatureComment comment)
	{
		if (sap.Comments == null)
		{
			sap.Comments = new List<PdfSignatureAppearance.SignatureComment>();
		}
		ParseFontCode(comment.FontColor, out var r, out var g, out var b);
		Font font = CalculateFont(comment.Font, comment.FontSize, comment.FontStyle, r, g, b);
		sap.Comments.Add(new PdfSignatureAppearance.SignatureComment
		{
			Font = font,
			Page = comment.Page,
			Rectangle = comment.Rectangle,
			Text = comment.Text
		});
	}

	private void AddImageAnnotation(PdfSignatureComment comment)
	{
		Image instance;
		try
		{
			instance = Image.GetInstance(Decode(comment.Background));
		}
		catch (Exception)
		{
			return;
		}
		float width = instance.Width;
		float scaledHeight = instance.ScaledHeight;
		instance.SetAbsolutePosition(0f, 0f);
		PdfTemplate frm = PdfTemplate.CreateTemplate(_stamper.Writer, width, scaledHeight);
		frm = NormalizeTemplate(frm, comment.Page, new Rectangle(comment.GetRectangle().Width, comment.GetRectangle().Height), comment.ID);
		frm.AddImage(instance);
		PdfAnnotation pdfAnnotation = PdfAnnotation.CreateStamp(_stamper.Writer, comment.GetRectangle(), null, comment.ID);
		pdfAnnotation.SetAppearance(PdfName.N, frm);
		pdfAnnotation.Flags = 68;
		pdfAnnotation.Title = _author;
		_stamper.AddAnnotation(pdfAnnotation, comment.Page);
	}

	private void AddTextAnnotation(PdfSignatureComment comment)
	{
		if (comment == null || comment.GetRectangle() == null)
		{
			return;
		}
		string[] array = comment.Rectangle.Split(',');
		try
		{
			int.Parse(array[0]);
			int.Parse(array[1]);
			int.Parse(array[2]);
			int.Parse(array[3]);
			PdfTemplate pdfTemplate = PdfTemplate.CreateTemplate(_stamper.Writer, comment.GetRectangle().Width, comment.GetRectangle().Height);
			ColumnText obj = new ColumnText(pdfTemplate)
			{
				RunDirection = 1
			};
			ParseFontCode(comment.FontColor, out var r, out var g, out var b);
			Phrase phrase = new Phrase(font: CalculateFont(comment.Font, comment.FontSize, comment.FontStyle, r, g, b), str: comment.Text);
			PdfPTable pdfPTable = new PdfPTable(1)
			{
				WidthPercentage = 100f
			};
			PdfPCell cell = new PdfPCell(phrase)
			{
				HorizontalAlignment = 0,
				VerticalAlignment = 4,
				FixedHeight = comment.GetRectangle().Height,
				Border = 0
			};
			pdfPTable.AddCell(cell);
			obj.SetSimpleColumn(0f, 0f, comment.GetRectangle().Width, comment.GetRectangle().Height);
			obj.AddElement(pdfPTable);
			obj.Go();
			PdfAnnotation pdfAnnotation = PdfAnnotation.CreateStamp(_stamper.Writer, comment.GetRectangle(), comment.Text, comment.ID);
			pdfAnnotation.Title = _author;
			pdfTemplate = NormalizeTemplate(pdfTemplate, comment.Page, new Rectangle(comment.GetRectangle().Width, comment.GetRectangle().Height), comment.ID);
			pdfAnnotation.SetAppearance(PdfName.N, pdfTemplate);
			pdfAnnotation.Flags = 68;
			_stamper.AddAnnotation(pdfAnnotation, comment.Page);
		}
		catch (Exception ex)
		{
			ex.LogExceptionToFile();
			throw;
		}
	}

	private Font CalculateFont(FontName fontName, int size, int style, int r, int g, int b)
	{
		if (size == 0)
		{
			size = 10;
		}
		_font = new Font(GetBaseFont(fontName), size);
		_font.SetColor(r, g, b);
		_font.SetStyle(style);
		return _font;
	}

	private static BaseFont GetBaseFont(FontName name)
	{
		_ = Resources.times;
		string name2;
		byte[] ttfAfm;
		switch (name)
		{
		case FontName.Roboto:
			name2 = "RobotoCondensed-Regular.ttf";
			ttfAfm = Resources.RobotoCondensed_Regular;
			break;
		case FontName.Arial:
			name2 = "tahoma.ttf";
			ttfAfm = Resources.tahoma;
			break;
		default:
			name2 = "times.ttf";
			ttfAfm = Resources.times;
			break;
		}
		return BaseFont.CreateFont(name2, "Identity-H", embedded: true, cached: false, ttfAfm, null);
	}

	private string CalculateSignatureFieldName(PdfReader reader, string fieldName)
	{
		try
		{
			string source = ((_signerName != null) ? _signerName.Replace(".", "_") : Guid.NewGuid().ToString());
			return $"{fieldName}-{source.ToSignatureFieldName()}-{Guid.NewGuid().GenFlake()}";
		}
		catch (Exception)
		{
			return Guid.NewGuid().ToString();
		}
	}

	private static void CalculateVisibleSignatureBorder(PdfSignatureAppearance sap, VisibleSigBorder borderType)
	{
		Rectangle rect = sap.Rect;
		PdfTemplate layer = sap.GetLayer(2);
		switch (borderType)
		{
		case VisibleSigBorder.DASHED:
			layer.SetRGBColorStroke(0, 0, 0);
			layer.SetLineDash(3f, 3f);
			layer.Rectangle(rect.Left, rect.Bottom, rect.Width, rect.Height);
			layer.Stroke();
			break;
		case VisibleSigBorder.LINE:
			layer.SetRGBColorStroke(0, 0, 0);
			layer.SetLineDash(1f);
			layer.Rectangle(rect.Left, rect.Bottom, rect.Width, rect.Height);
			layer.Stroke();
			break;
		}
	}

	private void Clear()
	{
		if (_outStream != null)
		{
			try
			{
				_outStream.Close();
				_outStream.Dispose();
			}
			catch (Exception)
			{
			}
		}
		if (_stamper != null)
		{
			try
			{
				_stamper.Close();
				_stamper.Dispose();
			}
			catch (Exception)
			{
			}
		}
	}

	public string GetSecondHashAsBase64()
	{
		byte[] secondHashBytes = GetSecondHashBytes();
		if (secondHashBytes == null)
		{
			return null;
		}
		return Convert.ToBase64String(secondHashBytes);
	}

	public byte[] GetSecondHashBytes()
	{
		try
		{
			CalculateSignature();
		}
		catch (Exception)
		{
			throw;
		}
		if (_signerInfoData != null)
		{
			if (_hashAlgorithm == MessageDigestAlgorithm.SHA256)
			{
				return SHA256.Create().ComputeHash(_signerInfoData);
			}
			if (_hashAlgorithm == MessageDigestAlgorithm.SHA1)
			{
				return SHA1.Create().ComputeHash(_signerInfoData);
			}
			return null;
		}
		return null;
	}

	public SignerProfile GetDataHashBytes()
	{
		byte[] array = null;
		try
		{
			array = GetSecondHashBytes();
		}
		catch (Exception)
		{
			throw;
		}
		return new SignerProfile
		{
			SecondHashBytes = array,
			DataHashBytes = _hashOnlyBytes,
			TempData = tempData,
			Fieldnames = _signatureViews?.Select((PdfSignatureView c) => c.Id).ToList(),
			Certchain = _certChain?.Select((Org.BouncyCastle.X509.X509Certificate c) => c.GetEncoded()).ToList(),
			EnableTimeStamp = _enableTimestamp,
			EnableLtv = _enableLTV,
			LtvTimeStamp = _addDocumentLvTimestamp,
			EstimatedSize = _signatureEstimatedSize,
			HashAlgorithm = HASH_ALGORITHM,
			TsaUrl = _tsaUrl,
			TsaUsername = _tsaUsername,
			TsaPassword = _tsaPassword,
			OwnerPassword = _ownerPassword
		};
	}

	public byte[] GetHashBytes()
	{
		return _signerInfoData;
	}

	public bool CheckHashSignature(string signedHashBase64)
	{
		try
		{
			byte[] signature = Convert.FromBase64String(signedHashBase64);
			ISigner signer = SignerUtilities.GetSigner(_hashAlgorithm.ToString() + "withRSA");
			Org.BouncyCastle.X509.X509Certificate x509Certificate = new X509CertificateParser().ReadCertificate(_signer.GetEncoded());
			signer.Init(forSigning: false, x509Certificate.GetPublicKey());
			signer.BlockUpdate(_signerInfoData, 0, _signerInfoData.Length);
			return signer.VerifySignature(signature);
		}
		catch (Exception)
		{
			throw;
		}
	}

	public void SetReason(string re)
	{
		_reason = re;
	}

	public void SetLocation(string loc)
	{
		_location = loc;
	}

	private static byte[] Decode(string text)
	{
		_ = text.Length;
		text = WebUtility.HtmlDecode(text);
		_ = text.Length;
		text = text.Replace('_', '/').Replace('-', '+');
		switch (text.Length % 4)
		{
		case 2:
			text += "==";
			break;
		case 3:
			text += "=";
			break;
		}
		return Convert.FromBase64String(text);
	}

	public void SetOptions(PDFSignParameter para)
	{
		if (!string.IsNullOrEmpty(para.ImageSrc))
		{
			try
			{
				byte[] customImage = Decode(para.ImageSrc);
				SetCustomImage(customImage);
			}
			catch (Exception innerException)
			{
				throw new Exception("Signature image is invalid base64 string.", innerException);
			}
		}
		SetRenderingMode((RenderMode)para.VisibleType);
		if (!string.IsNullOrEmpty(para.SignatureText))
		{
			SetLayer2Text(para.SignatureText);
		}
		if (para.FontSize < 4)
		{
			throw new Exception("Font size is too small. Greater than 3 required");
		}
		SetFontSize(para.FontSize);
		SetFontColor(para.FontColor);
		SetFontStyle((FontStyle)para.FontStyle);
		FontName fontName = FontName.Times_New_Roman;
		string fontName2 = para.FontName;
		if (!(fontName2 == "Roboto"))
		{
			if (fontName2 == "Arial")
			{
				fontName = FontName.Arial;
			}
		}
		else
		{
			fontName = FontName.Roboto;
		}
		SetFontName(fontName);
		if (para.Comment != null)
		{
			try
			{
				foreach (PdfSignatureComment item in para.Comment)
				{
					AddSignatureComment(item);
				}
			}
			catch (Exception)
			{
				throw new Exception("Add signature comments failed.");
			}
		}
		if (para.Signatures == null)
		{
			return;
		}
		try
		{
			foreach (PdfSignatureView signature in para.Signatures)
			{
				AddSignatureView(signature);
			}
		}
		catch (Exception)
		{
			throw new Exception("Add signature views failed.");
		}
	}

	public void SetSignaturePosition(int llx, int lly, int urx, int ury)
	{
		_rectangle = new Rectangle(llx, lly, urx, ury);
	}

	public void SetSigningPage(int page)
	{
		_page = page;
	}

	public void SetCustomImage(byte[] image)
	{
		if (image != null)
		{
			_customImage = image;
		}
		else
		{
			_customImage = Convert.FromBase64String(_defaultImage);
		}
	}

	public void SetFontName(FontName name)
	{
		_fontName = name;
	}

	public void SetFontStyle(FontStyle style)
	{
		_fontStyle = style;
	}

	public void SetFontSize(int size)
	{
		_fontSize = size;
	}

	public void SetFontColor(int r, int g, int b)
	{
		_r = ((r > -1 && r < 256) ? r : 0);
		_g = ((g > -1 && g < 256) ? g : 0);
		_b = ((b > -1 && b < 256) ? b : 0);
	}

	public void SetOwnerPassword(string password)
	{
		if (!string.IsNullOrEmpty(password))
		{
			_ownerPassword = Encoding.UTF8.GetBytes(password);
		}
	}

	public void SetFontColor(string colorcode)
	{
		if (string.IsNullOrEmpty(colorcode))
		{
			colorcode = "000000";
		}
		ParseFontCode(colorcode, out _r, out _g, out _b);
	}

	private void ParseFontCode(string colorcode, out int r, out int g, out int b)
	{
		r = 0;
		g = 0;
		b = 0;
		if (new Regex("^(?i)#?(([0-9a-fA-F]{2}){3}|([0-9a-fA-F]){3})$").IsMatch(colorcode))
		{
			colorcode = colorcode.Replace("#", "");
			int num = 1;
			if (new Regex("^(?i)(#?([0-9a-fA-F]{2}){3})$").IsMatch(colorcode))
			{
				num = 2;
			}
			r = int.Parse(colorcode.Substring(0, num), NumberStyles.HexNumber);
			g = int.Parse(colorcode.Substring(num, num), NumberStyles.HexNumber);
			b = int.Parse(colorcode.Substring(2 * num, num), NumberStyles.HexNumber);
		}
	}

	public void SetRenderingMode(RenderMode mode)
	{
		_renderMode = mode;
	}

	public void SetLayer2Text(string text)
	{
		_layer2Text = text;
	}

	public void SetVisibleAllPages(bool value)
	{
		_isVisibleAllPages = value;
	}

	public void AddSignatureComment(PdfSignatureComment comment)
	{
		if (_comments == null)
		{
			_comments = new List<PdfSignatureComment>();
		}
		if (comment != null)
		{
			_comments.Add(comment);
		}
	}

	public void AddSignatureView(PdfSignatureView view)
	{
		if (_signatureViews == null)
		{
			_signatureViews = new List<PdfSignatureView>();
		}
		if (_signatureViews != null)
		{
			_signatureViews.Add(view);
		}
	}

	public void SetSignatureBorderType(VisibleSigBorder type)
	{
		_borderType = type;
	}

	public void SetHashAlgorithm(MessageDigestAlgorithm alg)
	{
		_hashAlgorithm = alg;
		HASH_ALGORITHM = alg.ToString();
	}

	public void SetSigningTime(DateTime time)
	{
		if (_signer == null)
		{
			throw new Exception("Signer certificate is NULL");
		}
		if ((_signer.NotBefore - time).TotalSeconds > 0.0)
		{
			throw new Exception("Signer certificate not yet valid at signing time.");
		}
		if ((_signer.NotAfter - time).TotalSeconds < 0.0)
		{
			throw new Exception("Signer certificate expired at signing time.");
		}
		_dateTimeCreate = time;
	}

	public void SetAuthor(string author)
	{
		_author = author;
	}

	public string GetSignerSubjectDN()
	{
		try
		{
			return _signer.SubjectDN.ToString();
		}
		catch (Exception)
		{
			return null;
		}
	}

	public bool CheckHashSignature(byte[] signedBytes)
	{
		try
		{
			ISigner signer = SignerUtilities.GetSigner(_hashAlgorithm.ToString() + "withRSA");
			Org.BouncyCastle.X509.X509Certificate x509Certificate = new X509CertificateParser().ReadCertificate(_signer.GetEncoded());
			signer.Init(forSigning: false, x509Certificate.GetPublicKey());
			signer.BlockUpdate(_signerInfoData, 0, _signerInfoData.Length);
			return signer.VerifySignature(signedBytes);
		}
		catch (Exception)
		{
			throw;
		}
	}

	public bool CheckHashSignature(SignerProfile profile, byte[] signedBytes)
	{
		try
		{
			X509CertificateParser parser = new X509CertificateParser();
			_certChain = profile.Certchain.Select((byte[] c) => parser.ReadCertificate(c)).ToArray();
			byte[] array = new PdfPKCS7(null, _certChain, profile.HashAlgorithm, hasRSAdata: false).getAuthenticatedAttributeBytes(sigtype: profile.IsPades ? CryptoStandard.CADES : CryptoStandard.CMS, secondDigest: profile.DataHashBytes, ocsp: _ocsp, crlBytes: _clrs);
			ISigner signer = SignerUtilities.GetSigner(profile.HashAlgorithm + "withRSA");
			Org.BouncyCastle.X509.X509Certificate x509Certificate = parser.ReadCertificate(profile.Certchain.First());
			signer.Init(forSigning: false, x509Certificate.GetPublicKey());
			signer.BlockUpdate(array, 0, array.Length);
			return signer.VerifySignature(signedBytes);
		}
		catch (Exception)
		{
			throw;
		}
	}

	public byte[] Sign(byte[] signedBytes)
	{
		try
		{
			_sgn.SetExternalDigest(signedBytes, null, BaseHashSigner.ENCRYPT_ALGORITHM);
			byte[] array = new byte[_signatureEstimatedSize];
			X509CertificateParser x509CertificateParser = new X509CertificateParser();
			(new Org.BouncyCastle.X509.X509Certificate[1])[0] = x509CertificateParser.ReadCertificate(_signer.GetEncoded());
			CryptoStandard sigtype = (_isPades ? CryptoStandard.CADES : CryptoStandard.CMS);
			byte[] encodedPKCS = _sgn.GetEncodedPKCS7(_hashOnlyBytes, _tsa, _ocsp, _clrs, sigtype);
			Array.Copy(encodedPKCS, 0, array, 0, encodedPKCS.Length);
			PdfDictionary pdfDictionary = new PdfDictionary();
			pdfDictionary.Put(PdfName.CONTENTS, new PdfString(array).SetHexWriting(hexWriting: true));
			sap.Close(pdfDictionary);
			Clear();
			if (_enableLTV)
			{
				_unsignData = _outStream.ToArray();
				return EnableLtvSignature(_signatureViews.Select((PdfSignatureView c) => c.Id).ToList());
			}
			return _outStream.ToArray();
		}
		catch (Exception ex)
		{
			ex.LogExceptionToFile();
			return null;
		}
	}

	public byte[] Sign(SignerProfile profile, byte[] signedBytes)
	{
		try
		{
			X509CertificateParser parser = new X509CertificateParser();
			_certChain = profile.Certchain.Select((byte[] c) => parser.ReadCertificate(c)).ToArray();
			_ownerPassword = profile.OwnerPassword;
			if (!string.IsNullOrEmpty(profile.TsaUrl) && profile.EnableTimeStamp)
			{
				_tsa = new TSAClientBouncyCastleRewrite(profile.TsaUrl, profile.TsaUsername, profile.TsaPassword, 4096, "SHA-256");
				((TSAClientBouncyCastleRewrite)_tsa).SetDateTime(profile.SigTime);
			}
			_ocsp = profile.Ocsp;
			_clrs = profile.Clrs;
			PdfPKCS7 pdfPKCS = new PdfPKCS7(null, _certChain, profile.HashAlgorithm, hasRSAdata: false);
			pdfPKCS.SetExternalDigest(signedBytes, null, BaseHashSigner.ENCRYPT_ALGORITHM);
			byte[] signedBytes2 = pdfPKCS.GetEncodedPKCS7(sigtype: profile.IsPades ? CryptoStandard.CADES : CryptoStandard.CMS, secondDigest: profile.DataHashBytes, tsaClient: _tsa, ocsp: _ocsp, crlBytes: _clrs);
			PdfReader reader = ((_ownerPassword == null) ? new PdfReader(profile.TempData) : new PdfReader(profile.TempData, _ownerPassword));
			using MemoryStream memoryStream = new MemoryStream();
			IExternalSignatureContainer externalSignatureContainer = new MyExternalSignatureContainer(signedBytes2);
			MakeSignature.SignDeferred(reader, profile.Fieldnames.First(), memoryStream, externalSignatureContainer);
			if (_enableLTV)
			{
				_unsignData = memoryStream.ToArray();
				return EnableLtvSignature(profile.Fieldnames.ToList());
			}
			return memoryStream.ToArray();
		}
		catch (Exception)
		{
			throw;
		}
	}

	public string SignBase64(string signedHashBase64)
	{
		byte[] array = Sign(signedHashBase64);
		if (array != null)
		{
			return Convert.ToBase64String(array);
		}
		Console.WriteLine("Error when package signed data");
		return null;
	}

	public byte[] Sign(string signedHashBase64)
	{
		try
		{
			PdfPKCS7 pdfPKCS = new PdfPKCS7(null, _certChain, HASH_ALGORITHM, hasRSAdata: false);
			pdfPKCS.SetExternalDigest(Convert.FromBase64String(signedHashBase64), null, BaseHashSigner.ENCRYPT_ALGORITHM);
			byte[] destinationArray = new byte[_signatureEstimatedSize];
			X509CertificateParser x509CertificateParser = new X509CertificateParser();
			(new Org.BouncyCastle.X509.X509Certificate[1])[0] = x509CertificateParser.ReadCertificate(_signer.GetEncoded());
			CryptoStandard sigtype = (_isPades ? CryptoStandard.CADES : CryptoStandard.CMS);
			byte[] encodedPKCS = pdfPKCS.GetEncodedPKCS7(_hashOnlyBytes, _tsa, _ocsp, _clrs, sigtype);
			Array.Copy(encodedPKCS, 0, destinationArray, 0, encodedPKCS.Length);
			PdfReader reader = ((_ownerPassword == null) ? new PdfReader(tempData) : new PdfReader(tempData, _ownerPassword));
			using (MemoryStream memoryStream = new MemoryStream())
			{
				IExternalSignatureContainer externalSignatureContainer = new MyExternalSignatureContainer(encodedPKCS);
				foreach (PdfSignatureView signatureView in _signatureViews)
				{
					MakeSignature.SignDeferred(reader, signatureView.Id, memoryStream, externalSignatureContainer);
				}
				_outStream = memoryStream;
			}
			if (_enableLTV)
			{
				_unsignData = _outStream.ToArray();
				return EnableLtvSignature(_signatureViews.Select((PdfSignatureView c) => c.Id).ToList());
			}
			return _outStream.ToArray();
		}
		catch (Exception ex)
		{
			ex.LogExceptionToFile();
			throw;
		}
	}

	public void SetOcspRespnse(byte[] ocsp)
	{
		_ocsp = ocsp;
	}

	public void SetCrlResponse(ICollection<byte[]> clrs)
	{
		_clrs = clrs;
	}

	public bool SetSignerCertchain(ICollection<string> certs)
	{
		if (certs != null)
		{
			IList<Org.BouncyCastle.X509.X509Certificate> list = new List<Org.BouncyCastle.X509.X509Certificate>();
			int num = 0;
			foreach (string cert in certs)
			{
				if (string.IsNullOrEmpty(cert))
				{
					LogFile.LogToFile("PdfHashSigner.SetSignerCertchain(): certBase64 null");
					throw new CertificateVerificationException($"Certificate base64 string null at index {num}");
				}
				string text = cert.Trim();
				if (text.StartsWith("-----BEGIN CERTIFICATE-----"))
				{
					text = text.Replace("-----BEGIN CERTIFICATE-----", "").Replace("-----END CERTIFICATE-----", "");
				}
				try
				{
					Org.BouncyCastle.X509.X509Certificate item = new X509CertificateParser().ReadCertificate(Convert.FromBase64String(cert));
					list.Add(item);
				}
				catch (Exception ex)
				{
					LogFile.LogToFile("PdfHashSigner.SetSignerCertchain(): read certificate failed" + ex.Message);
					throw new CertificateVerificationException($"Malformed certificate format at index {num}");
				}
				num++;
			}
			_certChain = list.ToArray();
			return true;
		}
		return false;
	}

	public void EnableLTV(bool addDocumentLvTimestamp)
	{
		if (_certChain.Length < 2)
		{
			throw new LtvEnableFailureException("Certchain required");
		}
		if (_tsaUrl == null)
		{
			throw new LtvEnableFailureException("Ltv signature required TSA");
		}
		_enableTimestamp = true;
		_enableLTV = true;
		_addDocumentLvTimestamp = addDocumentLvTimestamp;
		try
		{
			_ocsp = CertificateHandle.GetOcspResponse(_certChain[0], _certChain[1]);
			_clrs = CertificateHandle.GetClrResponse(_certChain.ToList());
		}
		catch (LtvEnableFailureException)
		{
			throw;
		}
		catch (Exception ex2)
		{
			throw new LtvEnableFailureException(ex2.Message, ex2);
		}
	}

	private byte[] EnableAdobeLtv(List<string> fieldNames)
	{
		MemoryStream memoryStream = new MemoryStream();
		PdfReader pdfReader;
		PdfStamper pdfStamper;
		try
		{
			pdfReader = ((_ownerPassword == null) ? new PdfReader(_unsignData) : new PdfReader(_unsignData, _ownerPassword));
			pdfStamper = (_addDocumentLvTimestamp ? PdfStamper.CreateSignature(pdfReader, memoryStream, '\0', null, append: true, "VNPT TSA Document Timestamp ") : new PdfStamper(pdfReader, memoryStream, '\0', append: true));
		}
		catch (Exception ex)
		{
			pdfReader = ((_ownerPassword == null) ? new PdfReader(_unsignData) : new PdfReader(_unsignData, _ownerPassword));
			pdfStamper = (_addDocumentLvTimestamp ? PdfStamper.CreateSignature(pdfReader, memoryStream, '\0', null, append: false, "VNPT TSA Document Timestamp ") : new PdfStamper(pdfReader, memoryStream, '\0', append: false));
			ex.LogExceptionToFile();
		}
		AdobeLtvEnabling adobeLtvEnabling = new AdobeLtvEnabling(pdfStamper);
		OcspClientBouncyCastle ocspClient = new OcspClientBouncyCastle();
		CrlClientOnline crlClient = new CrlClientOnline();
		adobeLtvEnabling.Enable(ocspClient, crlClient);
		byte[] result = memoryStream.ToArray();
		if (pdfStamper != null)
		{
			try
			{
				pdfStamper.Close();
				pdfStamper.Dispose();
				pdfReader.Close();
				pdfReader.Dispose();
			}
			catch (Exception)
			{
			}
		}
		if (memoryStream != null)
		{
			try
			{
				memoryStream.Close();
				memoryStream.Dispose();
			}
			catch (Exception)
			{
			}
		}
		return result;
	}

	private byte[] EnableLtvSignature(List<string> fieldNames)
	{
		MemoryStream memoryStream = new MemoryStream();
		PdfReader pdfReader;
		PdfStamper pdfStamper;
		try
		{
			pdfReader = ((_ownerPassword == null) ? new PdfReader(_unsignData) : new PdfReader(_unsignData, _ownerPassword));
			pdfStamper = (_addDocumentLvTimestamp ? PdfStamper.CreateSignature(pdfReader, memoryStream, '\0', null, append: true, "VNPT TSA Document Timestamp ") : new PdfStamper(pdfReader, memoryStream, '\0', append: true));
		}
		catch (Exception ex)
		{
			pdfReader = ((_ownerPassword == null) ? new PdfReader(_unsignData) : new PdfReader(_unsignData, _ownerPassword));
			pdfStamper = (_addDocumentLvTimestamp ? PdfStamper.CreateSignature(pdfReader, memoryStream, '\0', null, append: false, "VNPT TSA Document Timestamp ") : new PdfStamper(pdfReader, memoryStream, '\0', append: false));
			ex.LogExceptionToFile();
		}
		LtvVerification ltvVerification = pdfStamper.LtvVerification;
		List<byte[]> list = new List<byte[]>();
		List<Org.BouncyCastle.X509.X509Certificate> list2 = new List<Org.BouncyCastle.X509.X509Certificate>();
		Org.BouncyCastle.X509.X509Certificate[] certChain = _certChain;
		foreach (Org.BouncyCastle.X509.X509Certificate x509Certificate in certChain)
		{
			list.Add(x509Certificate.GetEncoded());
			list2.Add(x509Certificate);
		}
		foreach (string fieldName in fieldNames)
		{
			ltvVerification.AddVerification(fieldName, (_ocsp != null) ? new List<byte[]> { _ocsp } : null, _clrs, list);
		}
		pdfStamper.Writer.AddDeveloperExtension(new PdfDeveloperExtension(PdfName.ADBE, new PdfName("1.7"), 8));
		if (_addDocumentLvTimestamp)
		{
			LtvTimestamp.Timestamp(pdfStamper.SignatureAppearance, _tsa, null);
		}
		byte[] result = memoryStream.ToArray();
		if (pdfStamper != null)
		{
			try
			{
				pdfStamper.Close();
				pdfStamper.Dispose();
				pdfReader.Close();
				pdfReader.Dispose();
			}
			catch (Exception)
			{
			}
		}
		if (memoryStream != null)
		{
			try
			{
				memoryStream.Close();
				memoryStream.Dispose();
			}
			catch (Exception)
			{
			}
		}
		return result;
	}

	public void SetSignatureStyle(SignatureStyle style)
	{
		_isPades = style == SignatureStyle.CADES;
	}

	public void EnableLTV(ICollection<byte[]> ocsps, ICollection<byte[]> clrs)
	{
		_enableLTV = true;
		if (ocsps != null && ocsps.Count > 0)
		{
			_ocsp = ocsps.ElementAt(0);
		}
		_clrs = clrs;
	}

	public SignerProfile GetSignerProfile()
	{
		byte[] array = null;
		try
		{
			array = GetSecondHashBytes();
		}
		catch (Exception)
		{
			throw;
		}
		return new SignerProfile
		{
			DocType = "PDF",
			SecondHashBytes = array,
			DataHashBytes = _hashOnlyBytes,
			TempData = tempData,
			Fieldnames = _signatureViews?.Select((PdfSignatureView c) => c.Id).ToList(),
			Certchain = _certChain?.Select((Org.BouncyCastle.X509.X509Certificate c) => c.GetEncoded()).ToList(),
			EnableTimeStamp = _enableTimestamp,
			EnableLtv = _enableLTV,
			LtvTimeStamp = _addDocumentLvTimestamp,
			EstimatedSize = _signatureEstimatedSize,
			HashAlgorithm = HASH_ALGORITHM,
			TsaUrl = _tsaUrl,
			TsaUsername = _tsaUsername,
			TsaPassword = _tsaPassword,
			SigTime = _dateTimeCreate,
			IsPades = _isPades,
			Ocsp = _ocsp,
			Clrs = _clrs
		};
	}

	public void EnableTimestamp()
	{
		_enableTimestamp = true;
	}
}
