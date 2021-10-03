using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Binary;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Tests.Core;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Arctium.Tests.Cryptography.HashFunctions
{
    public static class Skein_Tests
    {
        public static TestResult[] Run()
        {
            List<TestResult> results = new List<TestResult>();

            List<SkeinTest> tests = LoadVariousTests();
            List<SkeinTest> katTests = LoadKatTests();
            //List<SkeinTest> xLargeInputTests = LoadExtremelyLargeInputTests();

            foreach (SkeinTest test in tests) { RunTest(test, results); }
            foreach (SkeinTest test in katTests) { RunTest(test, results); }
            //foreach (SkeinTest test in xLargeInputTests) { RunTest(test, results); }

            return results.ToArray();
        }

        static void RunTest(SkeinTest test, List<TestResult> results)
        {
            TestResult result = new TestResult();
            result.Name = test.Name;
            byte[] actualResult = new byte[0];

            try
            {
                if (test.Type == "various")
                {
                    actualResult = ComputeHashTestVarious(test);
                }
                else if (test.Type == "kat")
                {
                    actualResult = ComputeHashTestKat(test);
                }
                else 
                {
                    actualResult = ComputeXt(test); 
                }

                result.Success = MemOps.Memcmp(actualResult, test.ExpectedHash);
            }
            catch (Exception e)
            {
                result.Success = false;
                result.Exception = e;
            }

            result.Success = MemOps.Memcmp(actualResult, test.ExpectedHash);
            results.Add(result);
        }

        static byte[] ComputeXt(SkeinTest test)
        {
            Skein_VAR skein = new Skein_VAR(Skein.InternalStateSize.Bits_512, test.ExpectedHash.Length * 8);

            byte[] input = new byte[100000 * test.Text.Length];

            for (int i = 0; i < test.Text.Length; i++) input[i] = test.Text[i % test.Text.Length];

            int fullBufCount = (test.Repeat * test.Text.Length) / input.Length;
            int lastBufCount = test.Repeat % (input.Length / test.Text.Length);


            for (int i =0; i < fullBufCount; i++)
            {
                skein.HashBytes(input);
                Console.WriteLine(fullBufCount - i);
            }

            skein.HashBytes(input, 0, lastBufCount * test.Text.Length);


            return skein.HashFinal();
        }

        static byte[] ComputeHashTestKat(SkeinTest test)
        {
            Skein_VAR skein = new Skein_VAR(Skein.InternalStateSize.Bits_512, test.HashSize);
            skein.HashBytes(test.Input);

            return skein.HashFinal();
        }

        static byte[] ComputeHashTestVarious(SkeinTest test)
        {
            byte[] actualResult = new byte[0];
            if (test.InternalStateSize == 256 && test.ExpectedHash.Length == 32)
            {
                Skein_256 s = new Skein_256();

                s.HashBytes(test.Input);
                actualResult = s.HashFinal();
            }
            else if (test.InternalStateSize == 512 && test.ExpectedHash.Length == 64)
            {
                Skein_512 s = new Skein_512();

                s.HashBytes(test.Input);
                actualResult = s.HashFinal();
            }
            else if (test.InternalStateSize == 1024 && test.ExpectedHash.Length == 128)
            {
                Skein_1024 s = new Skein_1024();
                
                s.HashBytes(test.Input);
                actualResult = s.HashFinal();
            }
            else
            {
                Skein_VAR s = new Skein_VAR((Skein.InternalStateSize)test.InternalStateSize, test.HashSize);

                s.HashBytes(test.Input);
                actualResult = s.HashFinal();
            }

            return actualResult;
        }

        private static List<SkeinTest> LoadExtremelyLargeInputTests()
        {
            return new List<SkeinTest>()
            {
                new SkeinTest()
                {
                    Name = "Hash Function / Skein / ExtremelyLargeInput / 1",
                    Type = "xt",
                    Repeat = 16777216,
                    Text = Encoding.ASCII.GetBytes("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"),
                    ExpectedHash = BinConverter.FromString("E07F56F9A844208558172F43754E120B7B8299BF44AC735A60FF521B"),
                }
            };
        }

        private static List<SkeinTest> LoadKatTests()
        {
            string[] katFiles = new string[] 
            {
                "ShortMsgKAT_224.txt",
                "ShortMsgKAT_256.txt",
                "ShortMsgKAT_384.txt",
                "ShortMsgKAT_512.txt",
                "LongMsgKAT_224.txt",
                "LongMsgKAT_256.txt", 
                "LongMsgKAT_384.txt",
                "LongMsgKAT_512.txt"
            };

            List<KatFile> parsed = new List<KatFile>();
            List<SkeinTest> tests = new List<SkeinTest>();

            foreach (string fname in katFiles)
            {
                parsed.Add(FileParser.ParseKAT(Files.GetFullPath(Files.SkeinTestVectorsDir + fname)));
            }

            foreach (KatFile kfile in parsed)
            {
                foreach (KatFileData kdata in kfile.KatFileData)
                {
                   if (kdata.Len % 8 != 0) continue;
                   tests.Add(new SkeinTest() 
                   {
                        Name = $"Hash Function / Skein(512, {kdata.MD.Length * 8}) / KAT({kdata.Msg.Length})",
                        ExpectedHash = kdata.MD,
                        HashSize = kdata.MD.Length * 8,
                        Input = kdata.Len > 0 ? kdata.Msg : new byte[0],
                        Type = "kat"
                   }); 
                }
            }

            return tests;
        }

        private static List<SkeinTest> LoadVariousTests()
        {
            List<SkeinTest> tests = new List<SkeinTest>();
            string fileName = Files.GetFullPath("HashFunctions/TestVectors/Skein/skeintests.txt");
            string[] lines = File.ReadAllLines(fileName);

            for (int i = 0; i < lines.Length; i+=4)
            {
                string internalSize = lines[i].Split(' ')[1].Split('-')[1];
                string hashSize = lines[i + 1].Split(' ')[1];
                string data = lines[i + 2].Split(' ')[1];
                string result = lines[i + 3].Split(' ')[1];

                tests.Add(new SkeinTest()
                {
                    ExpectedHash = BinConverter.FromString(result),
                    HashSize = int.Parse(hashSize),
                    Input = data != "(none)" ? BinConverter.FromString(data) : new byte[0],
                    InternalStateSize = int.Parse(internalSize),
                    Name = string.Format("Hash Function / Skein({0},{1}) / InputLen: {2} / various", internalSize, hashSize, data.Length / 2),
                    Type = "various"
                });
            }

            return tests;
        }

        static HashFunctionTest Skein256Cases()
        {
            return null;

        }

        static TestResult[] Skein512()
        {
            return new TestResult[0];
        }

        static TestResult[] Skein1024()
        {
            return new TestResult[0];
        }

    }

    class SkeinTest
    {
        public byte[] Input;
        public byte[] ExpectedHash;
        public int HashSize;
        public int InternalStateSize;
        public string Name;
        public string Type;
        public byte[] Text;
        public int Repeat;
    }
}
