using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Binary;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Tests.Core;
using Arctium.Tests.Core.Attributes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Tests.Cryptography.HashFunctions
{
    [TestsClass]
    class RIPEMD_Tests
    {
        [TestMethod]
        public List<TestResult> RIPEMD_160_Tests()
        {
            List<TestResult> result = new List<TestResult>();
            RIPEMD_160 ripe = new RIPEMD_160();


            return ExecuteHashFunctionTests.RunTests(ripe, RipeTests());
        }

        private List<HashFunctionTest> RipeTests()
        {
            List<HashFunctionTest> tests = new List<HashFunctionTest>();
            byte[] oneMilionA = new byte[1000000];
            for (int i = 0; i < 1000000; i++)
            {
                oneMilionA[i] = (byte)'a';
            }

            tests.Add(new HashFunctionTest(oneMilionA, BinConverter.FromString("52783243c1697bdbe16d37f97f68f08325dc1528"), "ripemd160 one milion a"));
            tests.Add(new HashFunctionTest(new byte[0], BinConverter.FromString("9c1185a5c5e9fc54612808977ee8f548b2258d31"), "ripemd160 empty array"));
            tests.Add(new HashFunctionTest(new byte[] { (byte)'a' }, BinConverter.FromString("0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"), "ripemd160 a"));
            tests.Add(new HashFunctionTest(new byte[] { (byte)'a', (byte)'b', (byte)'c' }, BinConverter.FromString("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"), "ripemd160 abc"));
            tests.Add(new HashFunctionTest(Encoding.ASCII.GetBytes("message digest"), BinConverter.FromString("5d0689ef49d2fae572b881b123a85ffa21595f36"), "ripemd160 message digest"));
            tests.Add(new HashFunctionTest(Encoding.ASCII.GetBytes("abcdefghijklmnopqrstuvwxyz"), BinConverter.FromString("f71c27109c692c1b56bbdceb5b9d2865b3708dbc"), "ripemd160 abcd...z digest"));
            tests.Add(new HashFunctionTest(Encoding.ASCII.GetBytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
                BinConverter.FromString("12a053384a9c0c88e405a06c27dcf49ada62eb2b"), "ripemd160 abcd...pnpq digest"));
            tests.Add(new HashFunctionTest(
                Encoding.ASCII.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
                BinConverter.FromString("b0e20b6e3116640286ed3a87a5713079b21f5189"),
                "ripemd160 ABC...789 digest"));
            tests.Add(new HashFunctionTest(Encoding.ASCII.GetBytes(string.Format("{0}{0}{0}{0}{0}{0}{0}{0}", "1234567890")),
                BinConverter.FromString("9b752e45573d4b39f4dbd3323cab82bf63326bfb"), "ripemd160 8 times 123456789 digest"));

            return tests;
        }
    }
}
