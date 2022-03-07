using Arctium.Cryptography.HashFunctions.CRC;
using Arctium.Tests.Core;
using Arctium.Tests.Core.Attributes;
using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Tests.Cryptography.HashFunctions.CRC
{
    [TestsClass]
    public class CRC32_ISCSI_Tests
    {
        public CRC32_ISCSI_Tests() { }

        [TestMethod]
        public List<TestResult> CRC32_C_StandardTests()
        {
            var tests = Tests();
            List<TestResult> testResults = new List<TestResult>();
            var crc32c = PredefinedCRC.CRC32_ISCSI();

            foreach (var test in tests)
            {
                crc32c.Reset();

                crc32c.Process(test.Key);

                var result = crc32c.Result();

                testResults.Add(new TestResult("CRC_32_ISCSI", result == test.Value));
            }

            return testResults;
        }

        private List<KeyValuePair<byte[], uint>> Tests()
        {
            return new List<KeyValuePair<byte[], uint>>()
            {
                Test(new byte[0], 0),
                Test(new byte[] { 0xE6 },  0x97EC1CA3 ),
                Test(new byte[] { 0xdd,0x9b,0xC3,0xE2,0xF1,0x33,0x22,0x11,0xE2,0xE1, },    0xF67AA5EA   ),
                Test(Encoding.ASCII.GetBytes("qwertyasdfzxcv!@#$"),  0x85B48EC4 ),
                Test(new byte[] { 0x00, 0x01, 0x02, 0x03, 0xff, 0xf3, 0xf1, 0x44, 0xe1 },  0xCB4D3C81 ),
            };
        }

        private KeyValuePair<byte[], uint> Test(byte[] bytes, uint result) => new KeyValuePair<byte[], uint>(bytes, result);
    }
}
