using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Shared.Helpers;
using Arctium.Tests.Core;
using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Tests.Cryptography.HashFunctions
{
    public static class JHTests
    {
        public static TestResult[] Run()
        {
            string jhDir = Files.JHTestVectorsDirFullPath;

            var short224 = FileParser.ParseKAT(jhDir + "ShortMsgKAT_224.txt");
            var short256 = FileParser.ParseKAT(jhDir + "ShortMsgKAT_256.txt");
            var short384 = FileParser.ParseKAT(jhDir + "ShortMsgKAT_384.txt");
            var short512 = FileParser.ParseKAT(jhDir + "ShortMsgKAT_512.txt");

            var long224 = FileParser.ParseKAT(jhDir + "LongMsgKAT_224.txt");
            var long256 = FileParser.ParseKAT(jhDir + "LongMsgKAT_256.txt");
            var long384 = FileParser.ParseKAT(jhDir + "LongMsgKAT_384.txt");
            var long512 = FileParser.ParseKAT(jhDir + "LongMsgKAT_512.txt");

            List<TestResult> results = new List<TestResult>();

            results.AddRange(ExecuteTests(new JH_224(), short224));
            results.AddRange(ExecuteTests(new JH_256(), short256));
            results.AddRange(ExecuteTests(new JH_384(), short384));
            results.AddRange(ExecuteTests(new JH_512(), short512));

            results.AddRange(ExecuteTests(new JH_224(), long224));
            results.AddRange(ExecuteTests(new JH_256(), long256));
            results.AddRange(ExecuteTests(new JH_384(), long384));
            results.AddRange(ExecuteTests(new JH_512(), long512));

            return results.ToArray();
        }

        public static TestResult[] RunLongTests()
        {
            /* Copy - paste from 'ExtremelyLongMsgKAT_' */

            return null;

        }

        static List<TestResult> ExecuteTests(JH hash, KatFile katFile)
        {
            List<TestResult> results = new List<TestResult>();

            try
            {
                foreach (var kfd in katFile.KatFileData)
                {
                    if (kfd.Len != 0 && kfd.Len % 8 != 0) continue;

                    hash.Reset();
                    
                    hash.HashBytes(kfd.Msg);
                    byte[] result = hash.HashFinal();

                    bool success = MemOps.Memcmp(result, kfd.MD);
                    results.Add(new TestResult($"JH_{hash.HashSizeBits} / KAT file name: {katFile.FileName} / Len: {kfd.Len}", success));
                }
            }
            catch (Exception e)
            {
                results.Add(new TestResult(e));
            }

            return results;
        }
    }
}
