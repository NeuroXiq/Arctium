using System.Collections.Generic;

namespace Arctium.Tests.Cryptography.HashFunctions
{
    public static class JHTests
    {
        public static List<HashFunctionTest> Short224;
        public static List<HashFunctionTest> Short256;
        public static List<HashFunctionTest> Short384;
        public static List<HashFunctionTest> Short512;

        public static List<HashFunctionTest> Long224 = new List<HashFunctionTest>();
        public static List<HashFunctionTest> Long256 = new List<HashFunctionTest>();
        public static List<HashFunctionTest> Long384 = new List<HashFunctionTest>();
        public static List<HashFunctionTest> Long512 = new List<HashFunctionTest>();

        static JHTests()
        {
            string jhDir = Files.JHTestVectorsDirFullPath;

            Short224 = HashFunctionTestHelper.LoadTestsFromSLKatFile("JH-224", Files.HashFunctions.JH224ShortMsgKat);
            Short256 = HashFunctionTestHelper.LoadTestsFromSLKatFile("JH-256", Files.HashFunctions.JH256ShortMsgKat);
            Short384 = HashFunctionTestHelper.LoadTestsFromSLKatFile("JH-384", Files.HashFunctions.JH384ShortMsgKat);
            Short512 = HashFunctionTestHelper.LoadTestsFromSLKatFile("JH-512", Files.HashFunctions.JH512ShortMsgKat);

            Short224.AddRange(HashFunctionTestHelper.LoadTestsFromSLKatFile("JH-224", Files.HashFunctions.JH224LongMsgKat));
            Short256.AddRange(HashFunctionTestHelper.LoadTestsFromSLKatFile("JH-256", Files.HashFunctions.JH256LongMsgKat));
            Short384.AddRange(HashFunctionTestHelper.LoadTestsFromSLKatFile("JH-384", Files.HashFunctions.JH384LongMsgKat));
            Short512.AddRange(HashFunctionTestHelper.LoadTestsFromSLKatFile("JH-512", Files.HashFunctions.JH512LongMsgKat));

            

            Long224.Add(HashFunctionTestHelper.LoadTestExtremelyLongAsStream("JH-224",
                16777216,
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
                "B4ABC2827D3547D19B517C673DE2DF2666AE95A0E73ECB213E5C95D4"));

            Long256.Add(HashFunctionTestHelper.LoadTestExtremelyLongAsStream("JH-256",
                16777216,
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
                "58FFBDE520764DFC03B29598ACD70655BB2C245A3D73FDD6EB9E1BC221AF579B"));

            Long384.Add(HashFunctionTestHelper.LoadTestExtremelyLongAsStream("JH-384",
                16777216,
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
                "836EC726CA5280BBC490A25389D1F507CECED047E9E3DAF0ED3DAA5D9AEDE2DDA89C8B7995F7855A3354AFBFFF1B4935"));

            Long512.Add(HashFunctionTestHelper.LoadTestExtremelyLongAsStream("JH-512",
                16777216,
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
                "A3053657024A43187CF8C1C82194D5D944A7408EE3B584801309292DEFF8080F88183B5642318456C7C05998C9A70D0F784E4C42D9EBCBA7F2CA25B3FBDE2CE5"));
        }
    }
}
