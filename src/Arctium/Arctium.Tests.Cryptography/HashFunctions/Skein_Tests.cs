using Arctium.Cryptography.HashFunctions.Hashes;
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
        const string TestNameFromat = "Hash Function / Skein({0},{1}) / InputLen: {2}";

        public static TestResult[] Run()
        {
            List<TestResult> results = new List<TestResult>();

            List<SkeinTest> tests = LoadSkeinTests();

            foreach (SkeinTest test in tests)
            {
                TestResult result = new TestResult();
                result.Name = string.Format(TestNameFromat, test.InternalStateSize, test.HashSize, test.Input.Length);
                byte[] actualResult = new byte[0];

                try
                {
                    actualResult = ComputeHash(test);
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

            return results.ToArray();
        }

        static byte[] ComputeHash(SkeinTest test)
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
                // Skein_1024 s = new Skein_1024();
                // 
                // s.HashBytes(test.Input);
                // actualResult = s.HashFinal();
            }
            else
            {
                Skein_VAR s = new Skein_VAR((Skein.InternalStateSize)test.InternalStateSize, test.HashSize);

                s.HashBytes(test.Input);
                actualResult = s.HashFinal();
            }

            return actualResult;
        }

        private static List<SkeinTest> LoadSkeinTests()
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
                    InternalStateSize = int.Parse(internalSize)
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
    }
}
