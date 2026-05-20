using System;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace SignService.Common.HashSignature.Common;

public static class LogFile
{
	public static string LogExceptionToFile(this Exception ex, LogFileType logType = LogFileType.EXCEPTION)
	{
		return LogToFile(string.Concat(ex.Message, Environment.NewLine, ex.Source, Environment.NewLine, ex.StackTrace, Environment.NewLine + "   \t\t", ex.TargetSite, Environment.NewLine + "   \t\t", ex.InnerException), logType);
	}

	public static void LogService(object[] retObj101, LogFileType logType = LogFileType.LOGSERVICE)
	{
		if (retObj101 != null && retObj101.ToList().Count > 0)
		{
			LogToFile(retObj101.Aggregate("", (string current, object t) => current + t.ToString()), logType);
		}
		else
		{
			LogToFile("retObj trả về null ", logType);
		}
	}

	public static string LogToFileControl<T>(T objectT, string logMessage, LogFileType logType = LogFileType.TRACE, string pathLog = "")
	{
		logMessage = objectT.GetType().Name + "\t" + logMessage;
		return LogToFile(logMessage, logType, pathLog);
	}

	public static string LogToFile(string logMessage, LogFileType logType = LogFileType.TRACE, string pathLog = "")
	{
		string text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "VNPT-IT/VnptHashSignatures_net50");
		Path.GetDirectoryName(Environment.GetCommandLineArgs()[0]);
		string text2 = text;
		string text3 = ((!string.IsNullOrEmpty(pathLog)) ? pathLog : (text2 + "\\" + DateTime.Today.ToString("yyyyMMdd")));
		string text4 = ".log";
		string text5 = ".0" + text4;
		if (!Directory.Exists(text3))
		{
			Directory.CreateDirectory(text3);
			_ = text3 + "\\" + logType.ToString() + text5;
		}
		int num = 0;
		string text6;
		while (true)
		{
			text6 = text3 + "\\" + logType.ToString() + "." + num + text4;
			if (!File.Exists(text6) || !((float)new FileInfo(text6).Length / 1024f / 1024f > 5f))
			{
				break;
			}
			num++;
		}
		logMessage = DateTime.Now.ToString("HH:mm:ss") + " " + logMessage;
		if (string.IsNullOrEmpty(text6))
		{
			return "";
		}
		TextWriterTraceListener textWriterTraceListener = new TextWriterTraceListener(text6);
		textWriterTraceListener.WriteLine(logMessage);
		textWriterTraceListener.Flush();
		textWriterTraceListener.Close();
		return text6;
	}
}
