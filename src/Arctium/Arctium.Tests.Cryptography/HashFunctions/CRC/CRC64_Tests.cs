using Arctium.Cryptography.HashFunctions.CRC;
using Arctium.Tests.Core;
using Arctium.Tests.Core.Attributes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Tests.Cryptography.HashFunctions.CRC
{
    [TestsClass]
    public class CRC64_Tests
    {
        [TestMethod]
        public List<TestResult> CRC32_C_StandardTests()
        {
            var tests = Tests();
            var inputBytes = InputBytes();

            List<TestResult> testResults = new List<TestResult>();

            foreach (var test in tests)
            {
                var testname = $"{test.Key.Name} / poly: {test.Key.Polynomial.ToString("X16")}";
                var crc8Instance = test.Key;

                crc8Instance.Process(inputBytes);
                var result = crc8Instance.Result();

                testResults.Add(new TestResult(testname, result == test.Value));
            }

            return testResults;
        }


        private List<KeyValuePair<CRC64, ulong>> Tests()
        {
            return new List<KeyValuePair<CRC64, ulong>>()
            {
                Test(PredefinedCRC.CRC64_MS(), 0x73010E7725BCD180),
                Test(PredefinedCRC.CRC64_WE(), 0x59C3325B2927A19A),
                Test(PredefinedCRC.CRC64_XZ(), 0x72414B2F65DB3AB0),
            };
        }

        private KeyValuePair<CRC64, ulong> Test(CRC64 crc64, ulong result) => new KeyValuePair<CRC64, ulong>(crc64, result);

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
