using Arctium.Shared.Helpers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Arctium.Tests.Cryptography.HashFunctions
{
    public static class Skein_Tests
    {
        public static List<HashFunctionTest> Short512_224;
        public static List<HashFunctionTest> Short512_256;
        public static List<HashFunctionTest> Short512_384;
        public static List<HashFunctionTest> Short512_512;
        public static List<HashFunctionTest> Short512_1024;

        public static List<HashFunctionTest> Short256_224;
        public static List<HashFunctionTest> Short256_256;
        public static List<HashFunctionTest> Short256_384;
        public static List<HashFunctionTest> Short256_512;
        public static List<HashFunctionTest> Short256_1024;

        public static List<HashFunctionTest> Short1024_224;
        public static List<HashFunctionTest> Short1024_256;
        public static List<HashFunctionTest> Short1024_384;
        public static List<HashFunctionTest> Short1024_512;
        public static List<HashFunctionTest> Short1024_1024;
        public static List<HashFunctionTest> Long512_224;

        static Skein_Tests()
        {
            Short512_224 = HashFunctionTestHelper.LoadTestsFromSLKatFile("Skein-512-224", Files.HashFunctions.Skein224ShortMsgKat);
            Short512_256 = HashFunctionTestHelper.LoadTestsFromSLKatFile("Skein-512-256", Files.HashFunctions.Skein256ShortMsgKat);
            Short512_384 = HashFunctionTestHelper.LoadTestsFromSLKatFile("Skein-512-384", Files.HashFunctions.Skein384ShortMsgKat);
            Short512_512 = HashFunctionTestHelper.LoadTestsFromSLKatFile("Skein-512-512", Files.HashFunctions.Skein512ShortMsgKat);
            Short512_224.AddRange(HashFunctionTestHelper.LoadTestsFromSLKatFile("Skein-512-224", Files.HashFunctions.Skein224LongMsgKat));
            Short512_256.AddRange(HashFunctionTestHelper.LoadTestsFromSLKatFile("Skein-512-256", Files.HashFunctions.Skein256LongMsgKat));
            Short512_384.AddRange(HashFunctionTestHelper.LoadTestsFromSLKatFile("Skein-512-384", Files.HashFunctions.Skein384LongMsgKat));
            Short512_512.AddRange(HashFunctionTestHelper.LoadTestsFromSLKatFile("Skein-512-512", Files.HashFunctions.Skein512LongMsgKat));

            Short512_1024 = new List<HashFunctionTest>();

            Short256_224 = new List<HashFunctionTest>();
            Short256_256 = new List<HashFunctionTest>();
            Short256_384 = new List<HashFunctionTest>();
            Short256_512 = new List<HashFunctionTest>();
            Short256_1024 = new List<HashFunctionTest>();
            Short1024_224 = new List<HashFunctionTest>();
            Short1024_256 = new List<HashFunctionTest>();
            Short1024_384 = new List<HashFunctionTest>();
            Short1024_512 = new List<HashFunctionTest>();
            Short1024_1024= new List<HashFunctionTest>();

            Long512_224 = new List<HashFunctionTest>();
            Long512_224.Add(HashFunctionTestHelper.LoadTestExtremelyLongAsStream("Skein-512-224",
                16777216,
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
                "E07F56F9A844208558172F43754E120B7B8299BF44AC735A60FF521B"));

            LoadVariousTests();
        }

        private static void LoadVariousTests()
        {
            string[] lines = File.ReadAllLines(Files.HashFunctions.SkeinSkeinTestsTxt);

            for (int i = 0; i < lines.Length; i+=4)
            {
                string internalSize = lines[i].Split(' ')[1].Split('-')[1];
                string hashSize = lines[i + 1].Split(' ')[1];
                string data = lines[i + 2].Split(' ')[1];
                string result = lines[i + 3].Split(' ')[1];

                int internalSizeInt = int.Parse(internalSize);
                int hashSizeInt = int.Parse(hashSize);
                byte[] expectedHash = BinConverter.FromString(result);
                byte[] input = data == "(none)" ? new byte[0] : BinConverter.FromString(data);

                var test = new HashFunctionTest(input, expectedHash, $"Skein-{internalSizeInt}-{hashSizeInt}");

                if (internalSizeInt == 256 && hashSizeInt == 224)  Short256_224.Add(test);
                if (internalSizeInt == 256 && hashSizeInt == 256)  Short256_256.Add(test);
                if (internalSizeInt == 256 && hashSizeInt == 384)  Short256_384.Add(test);
                if (internalSizeInt == 256 && hashSizeInt == 512)  Short256_512.Add(test);
                if (internalSizeInt == 256 && hashSizeInt == 1024) Short256_1024.Add(test);

                if (internalSizeInt == 512 && hashSizeInt == 224)  Short512_224.Add(test);
                if (internalSizeInt == 512 && hashSizeInt == 256)  Short512_256.Add(test);
                if (internalSizeInt == 512 && hashSizeInt == 384)  Short512_384.Add(test);
                if (internalSizeInt == 512 && hashSizeInt == 512)  Short512_512.Add(test);
                if (internalSizeInt == 512 && hashSizeInt == 1024) Short512_1024.Add(test);

                if (internalSizeInt == 1024 && hashSizeInt == 224)  Short1024_224.Add(test);
                if (internalSizeInt == 1024 && hashSizeInt == 256)  Short1024_256.Add(test);
                if (internalSizeInt == 1024 && hashSizeInt == 384)  Short1024_384.Add(test);
                if (internalSizeInt == 1024 && hashSizeInt == 512)  Short1024_512.Add(test);
                if (internalSizeInt == 1024 && hashSizeInt == 1024) Short1024_1024.Add(test);
            }
        }
    }
}
