using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Shared.Helpers.Binary;
using Arctium.Tests.Core;
using Arctium.Tests.Core.Attributes;
using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Tests.Cryptography.HashFunctions
{
    [TestsClass]
    public class SHA1Tests
    {
        public static List<HashFunctionTest> Short;

        static SHA1Tests()
        {
            Short = GetShortTests();
        }

        private static List<HashFunctionTest> GetShortTests()
        {
            return new List<HashFunctionTest>()
            {
                Test(0, "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
                Test(1, "6dcd4ce23d88e2ee9568ba546c007c63d9131c1b"),
                Test(2, "801c34269f74ed383fc97de33604b8a905adb635"),
                Test(3, "606ec6e9bd8a8ff2ad14e5fade3f264471e82251"),
                Test(4, "e2512172abf8cc9f67fdd49eb6cacf2df71bbad3"),
                Test(5, "c1fe3a7b487f66a6ac8c7e4794bc55c31b0ef403"),

                Test(53, "55066b480654e5846549494b863e3cd34bae76eb"),
                Test(54, "18b837ae2f9a204a7fea6d6a2ae5174365137861"),
                Test(55, "5021b3d42aa093bffc34eedd7a1455f3624bc552"),
                Test(56, "6b45e3cf1eb3324b9fd4df3b83d89c4c2c4ca896"),
                Test(57, "e8d6ea5c627fc8676fa662677b028640844dc35c"),
                Test(58, "e0ed6b6f61dae4219379cf9fe19565150c8e6046"),
                Test(59, "ba83959b9f4a8b3ca082d501e7b75ce73992e35f"),

                Test(60, "c9c4571630054c5466d19b5ea28069dc71c72b68"),
                Test(61, "fc202c022fdc439b99892020e04fc93b4ee8448a"),
                Test(62, "0dc94299f2d293a48173f9c78a882f8a9bffe3b0"),
                Test(64, "30b86e44e6001403827a62c58b08893e77cf121f"),

                Test(65, "826b7e7a7af8a529ae1c7443c23bf185c0ad440c"),
                Test(66, "eddee92010936db2c45d2c9f5fdd2726fcd28789"),


                Test(119, "293e3964d2b4d4ba9d21991b8388283b4f09b935"),
                Test(120, "a1298700a534e357b7130c74e277fe5428d43baf"),
                Test(121, "b9bd07da310bbf697d195fd2c2440d567f33ea95"),
                Test(122, "d712ce221db9a78a2ed64fdc5f3d6758c1cb3c46"),
                Test(123, "932567a1cfc045b729abdb52ed6c5c6acf59f369"),
                Test(124, "f84d4ec48808a1b0afe0b1e2c62a5dccf52f9ccf"),
                Test(125, "9d3953e922387b19a2f0e7f27ca2b790dbe57dfb"),
                Test(126, "2ae9e1bd10bc490766de002cd5b73917680cc26e"),
                Test(127, "8c8393ac8939430753d7cb568e2f2237bc62d683"),
                Test(128, "2927490ade868795ecdd8febe05214cbd243ef35"),
                Test(129, "a61aecbe0691f04f4c4dae8770187c24f1ef0fe9"),
            };
        }

        private static HashFunctionTest Test(int aCount, string hash)
        {
            return new HashFunctionTest(Encoding.ASCII.GetBytes(new String('A', aCount)),
                BinConverter.FromString(hash),
                $"SHA1 / A COUNT: {aCount}");
        }

        [TestMethod]
        public List<TestResult> SHA1_ShortTests()
        {
            return ExecuteHashFunctionTests.RunTests(new SHA1(), Short);
        }
    }
}
