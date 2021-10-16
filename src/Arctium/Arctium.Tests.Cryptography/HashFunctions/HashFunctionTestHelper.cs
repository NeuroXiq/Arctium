using Arctium.Shared.Helpers.Binary;
using Arctium.Tests.Core;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Arctium.Tests.Cryptography.HashFunctions
{
    static class HashFunctionTestHelper
    {
        public static List<HashFunctionTest> LoadTestsFromSLKatFile(string hashFunName, string path)
        {
            SLMsgKatFile slmkf = FileParser.ParseSLMKatFile(path);

            List<HashFunctionTest> tests = new List<HashFunctionTest>();

            foreach (var data in slmkf.Data)
            {
                if (data.Len % 8 == 0)
                {
                    string name = $"{hashFunName} / KAT {slmkf.FileName} / Len: {data.Len }";
                    var t = new HashFunctionTest(data.Len > 0 ? data.Msg : new byte[0], data.MD);

                    t.Name = name;
                    tests.Add(t);
                }
            }

            return tests;
        }

        public static HashFunctionTest LoadTestExtremelyLongAsStream(string hashFunName, int repeatCount, string text, string md)
        {
            RepeatStream s = new RepeatStream(Encoding.ASCII.GetBytes(text), repeatCount * text.Length, 5 * 1024 * 1024, 10 * 1024 * 1024);

            return new HashFunctionTest(s, BinConverter.FromString(md), $"{hashFunName} / Extremely Long / {text}");
        }
    }
}
