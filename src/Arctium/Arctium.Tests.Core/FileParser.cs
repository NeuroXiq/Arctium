using System;
using Arctium.Shared.Helpers.Binary;
using System.Collections.Generic;
using System.Text;
using System.IO;

namespace Arctium.Tests.Core
{
    public static class FileParser
    {
        public static KatFile ParseKAT(string file)
        {
            string[] allLines = File.ReadAllLines(file);
            List<KatFileData> katFileData = new List<KatFileData>();

            for (int i = 0; i < allLines.Length; i++)
            {
                if (allLines[i].StartsWith("Len"))
                {
                    string len = allLines[i].Split(' ')[2];
                    string msg = allLines[i + 1].Split(' ')[2];
                    string md = allLines[i + 2].Split(' ')[2];

                    katFileData.Add(new KatFileData() 
                    {
                       Len = long.Parse(len),
                       Msg = len != "0" ? BinConverter.FromString(msg) : new byte[0],
                       MD = BinConverter.FromString(md)
                    });
                }
            }

            return new KatFile()
            {
                FileName = Path.GetFileName(file),
                KatFileData = katFileData.ToArray()
            };
        }

        public static SLMsgKatFile ParseSLMKatFile(string file)
        {
            string[] allLines = File.ReadAllLines(file);
            List<SLMsgKatFile.KatFileData> katFileData = new List<SLMsgKatFile.KatFileData>();

            for (int i = 0; i < allLines.Length; i++)
            {
                if (allLines[i].StartsWith("Len"))
                {
                    string len = allLines[i].Split(' ')[2];
                    string msg = allLines[i + 1].Split(' ')[2];
                    string md = allLines[i + 2].Split(' ')[2];

                    katFileData.Add(new SLMsgKatFile.KatFileData()
                    {
                        Len = long.Parse(len),
                        Msg = len != "0" ? BinConverter.FromString(msg) : new byte[0],
                        MD = BinConverter.FromString(md)
                    });
                }
            }

            return new SLMsgKatFile()
            {
                FileName = Path.GetFileName(file),
                Data = katFileData.ToArray()
            };
        }
    }

    public class SLMsgKatFile
    {
        public string FileName;
        public KatFileData[] Data;

        public class KatFileData
        {
            public long Len;
            public byte[] Msg;
            public byte[] MD;
        }
    }

    public class KatFile
    {
        public string FileName;
        public KatFileData[] KatFileData;
    }

    public class KatFileData
    {
        public long Len;
        public byte[] Msg;
        public byte[] MD;
    }
}
