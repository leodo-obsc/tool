using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace SignService.Common.HashSignature.Common;

public static class Utils
{
	private const string TIME_FORMAT = "yyyy-MM-ddTHH:mm:ssZ";

	private static List<string> _lstKyTuDacBiet = new List<string>
	{
		"!", "\"", "#", "$", "%", "&", "'", "(", ")", "*",
		"+", ",", "-", ".", "/", ":", ";", "<", "=", ">",
		"?", "@", "[", "\\", "]", "^", "_", "`", "{", "|",
		"}", "~"
	};

	public static string ConvertDateToStringTZ(DateTime? t)
	{
		if (t.HasValue)
		{
			try
			{
				return t.Value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
			}
			catch (Exception)
			{
			}
		}
		return null;
	}

	public static string ToSignatureFieldName(this string source)
	{
		if (string.IsNullOrEmpty(source))
		{
			return "";
		}
		source = source.Trim();
		_lstKyTuDacBiet.ForEach(delegate(string c)
		{
			source = source.Replace(c, "");
		});
		Regex regex = new Regex("\\p{IsCombiningDiacriticalMarks}+");
		string input = source.Normalize(NormalizationForm.FormD);
		input = regex.Replace(input, string.Empty).Replace('Đ', 'D').Replace('đ', 'd');
		return Regex.Replace(input, "[^a-zA-Z0-9_.-]+", " ", RegexOptions.Compiled);
	}

	public static string GenFlake(this Guid source)
	{
		return source.ToString().Substring(0, 12).Replace("-", "");
	}
}
