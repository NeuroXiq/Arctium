using Arctium.Cryptography.HashFunctions.CRC;
using Arctium.Tests.Core;
using Arctium.Tests.Core.Attributes;
using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Tests.Cryptography.HashFunctions.CRC
{
    [TestsClass]
    public class CRC_8_Tests
    {
        public CRC_8_Tests() { }

        [TestMethod]
        public List<TestResult> CRC32_C_StandardTests()
        {
            var tests = Tests();
            var inputBytes = InputBytes();

            List<TestResult> testResults = new List<TestResult>();

            foreach (var test in tests)
            {
                var testname = $"{test.Key.GetType().Name} / poly: {test.Key.Polynomial.ToString("X8")}";
                var crc8Instance = test.Key;

                crc8Instance.Process(inputBytes);
                var result = crc8Instance.Result();

                testResults.Add(new TestResult(testname, result == test.Value));
            }

            return testResults;
        }

        private List<KeyValuePair<CRC8, byte>> Tests()
        {
            return new List<KeyValuePair<CRC8, byte>>()
            {
                Test(PredefinedCRC.CRC8_DVB_S2(), 0xCA),
                Test(PredefinedCRC.CRC8_AUTOSAR(), 0x06),
                Test(PredefinedCRC.CRC8_MAXIM_DOW(), 0x18),
                Test(PredefinedCRC.CRC8_CDMA2000(), 0x41),
                Test(PredefinedCRC.CRC8_DARD(), 0x3C),
                Test(PredefinedCRC.CRC8_GSMA(), 0x3E),
            };
        }

        private KeyValuePair<CRC8, byte> Test(CRC8 crc8, byte result) => new KeyValuePair<CRC8, byte>(crc8, result);

        private byte[] InputBytes()
        {
            byte[] bytes = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                bytes[i] = (byte)i;
            }

            return bytes;
        }
    }
}
