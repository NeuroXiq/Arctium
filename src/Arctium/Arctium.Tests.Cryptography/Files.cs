namespace Arctium.Tests.Cryptography
{
    public static class Files
    {
        static string HFTV => GetFullPath("HashFunctions/TestVectors/");
        static string CIPH => GetFullPath("ciphers-test-vectors/");

        public static string JHTestVectorsDirFullPath => GetFullPath("HashFunctions/TestVectors/JH/");

        static string CryptographyFilesFolder = null;

        public static class HashFunctions
        {
            public static readonly string JH224ShortMsgKat = HFTV + "JH/ShortMsgKAT_224.txt";
            public static readonly string JH256ShortMsgKat = HFTV + "JH/ShortMsgKAT_256.txt";
            public static readonly string JH384ShortMsgKat = HFTV + "JH/ShortMsgKAT_384.txt";
            public static readonly string JH512ShortMsgKat = HFTV + "JH/ShortMsgKAT_512.txt";

            public static readonly string JH224LongMsgKat = HFTV + "JH/LongMsgKAT_224.txt";
            public static readonly string JH256LongMsgKat = HFTV + "JH/LongMsgKAT_256.txt";
            public static readonly string JH384LongMsgKat = HFTV + "JH/LongMsgKAT_384.txt";
            public static readonly string JH512LongMsgKat = HFTV + "JH/LongMsgKAT_512.txt";

            public static readonly string SHA3224ShortMsg = HFTV + "SHA3/SHA3_224ShortMsg.rsp";
            public static readonly string SHA3256ShortMsg = HFTV + "SHA3/SHA3_256ShortMsg.rsp";
            public static readonly string SHA3384ShortMsg = HFTV + "SHA3/SHA3_384ShortMsg.rsp";
            public static readonly string SHA3512ShortMsg = HFTV + "SHA3/SHA3_512ShortMsg.rsp";

            public static readonly string SHA3224LongMsg = HFTV + "SHA3/SHA3_224LongMsg.rsp";
            public static readonly string SHA3256LongMsg = HFTV + "SHA3/SHA3_256LongMsg.rsp";
            public static readonly string SHA3384LongMsg = HFTV + "SHA3/SHA3_384LongMsg.rsp";
            public static readonly string SHA3512LongMsg = HFTV + "SHA3/SHA3_512LongMsg.rsp";

            public static readonly string Skein224ShortMsgKat = HFTV + "Skein/ShortMsgKAT_224.txt";
            public static readonly string Skein256ShortMsgKat = HFTV + "Skein/ShortMsgKAT_256.txt";
            public static readonly string Skein384ShortMsgKat = HFTV + "Skein/ShortMsgKAT_384.txt";
            public static readonly string Skein512ShortMsgKat = HFTV + "Skein/ShortMsgKAT_512.txt";
            public static readonly string Skein224LongMsgKat = HFTV + "Skein/LongMsgKAT_224.txt";
            public static readonly string Skein256LongMsgKat = HFTV + "Skein/LongMsgKAT_256.txt";
            public static readonly string Skein384LongMsgKat = HFTV + "Skein/LongMsgKAT_384.txt";
            public static readonly string Skein512LongMsgKat = HFTV + "Skein/LongMsgKAT_512.txt";
            public static readonly string SkeinSkeinTestsTxt = HFTV + "Skein/skeintests.txt";

            public static readonly string Blake2b512TestVectors = HFTV + "BLAKE2/Blake2b_512_TestVectors.txt";
            public static readonly string Blake3TestVectors = HFTV + "BLAKE3/BLAKE3TestVectors.txt";

            public static readonly string RadioGatun64TestVectors = HFTV + "radiogatun/RG64-testvectors";
            public static readonly string RadioGatun32TestVectors = HFTV + "radiogatun/RG32-testvectors";
            public static readonly string Streebog512TestVectors = HFTV + "streebog/v512.txt";
            public static readonly string Streebog256TestVectors = HFTV + "streebog/v256.txt";
            public static readonly string HMAC_NIST = HFTV + "HMAC_NIST.rsp";
        }

        public static class Ciphers
        {
            public static readonly string Camellia128 = CIPH + "camellia/camellia-128.txt";
            public static readonly string Camellia192 = CIPH + "camellia/camellia-192.txt";
            public static readonly string Camellia256 = CIPH + "camellia/camellia-256.txt";
        }

        public static void SetArctiumFilesPath(string fullPath)
        {
            CryptographyFilesFolder = fullPath + "/" + "Tests/Arctium_Tests_Cryptography/";
        }

        public static string GetFullPath(string fileName)
        {
            return CryptographyFilesFolder + fileName;
        }
    }
}
