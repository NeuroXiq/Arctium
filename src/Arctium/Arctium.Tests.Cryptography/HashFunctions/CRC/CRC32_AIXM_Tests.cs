using Arctium.Cryptography.HashFunctions.CRC;
using Arctium.Tests.Core;
using Arctium.Tests.Core.Attributes;
using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Tests.Cryptography.HashFunctions.CRC
{
    [TestsClass]
    public class CRC32_AIXM_Tests
    {
        public CRC32_AIXM_Tests() { }

        [TestMethod]
        public List<TestResult> CRC32_Q_StandardTests()
        {
            var tests = Tests();
            List<TestResult> testResults = new List<TestResult>();
            var crc32c = PredefinedCRC.CRC32_AIXM();

            foreach (var test in tests)
            {
                crc32c.Reset();

                crc32c.Process(test.Key);

                var result = crc32c.Result();

                testResults.Add(new TestResult("CRC32_AIXM", result == test.Value));
            }

            return testResults;
        }

        private List<KeyValuePair<byte[], uint>> Tests()
        {
            return new List<KeyValuePair<byte[], uint>>()
            {
                Test(new byte[0], 0),
                Test(new byte[] { 0xE6 },  0x155535F5),
                Test(new byte[] {
                    0xdd,0x9b,0xC3,0xE2,0xF1,0x33,0x22,0x11,0xE2,0xE1,
                    0x01,0x02,0x03,0x04,0xF1,0x33,0xff,0xee,0xdd,0xaa,
                    0xdd,0x9b,0x81,0x90,0xF6,0xe5,0xd3,0xc3,0xb2,0xa1,
                },     0x9EE3D727    ),
                Test(Encoding.ASCII.GetBytes("qwertyasdfzxcv!@#$"),   0x02E61896  ),
                Test(new byte[] { 0x00, 0x01, 0x02, 0x03, 0xff, 0xf3, 0xf1, 0x44, 0xe1 },   0x329CFEF2  ),
            };
        }

        private KeyValuePair<byte[], uint> Test(byte[] bytes, uint result) => new KeyValuePair<byte[], uint>(bytes, result);
    }
}
