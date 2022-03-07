using Arctium.Cryptography.HashFunctions.CRC;
using Arctium.Tests.Core;
using Arctium.Tests.Core.Attributes;
using System;
using System.Collections.Generic;

namespace Arctium.Tests.Cryptography.HashFunctions.CRC
{
    [TestsClass]
    public class CRC32Tests
    {
        public CRC32Tests()
        {

        }

        [TestMethod]
        public List<TestResult> CRC32_Tests()
        {
            List<TestResult> results = new List<TestResult>();
            var crcInputReflectedFalse = new CRC32(CRC32.DefaultPolynomial,
                CRC32.DefaultInitialValue,
                false,
                CRC32.DefaultResultReflected,
                CRC32.DefaultFinalXorValue);

            var customized = new CRC32(0x12345678,
                0xabcdef12,
                false,
                false,
                0x9876adcf);

            results.AddRange(Run("CRC-32 / Default Instance", DefaultInstanceTests(), new CRC32()));
            results.AddRange(Run("CRC-32 / InputReflectedFalse Instance", InputReflectedFalse(), crcInputReflectedFalse));
            results.AddRange(Run("CRC-32 / Default Customized", CustomizedValues(), customized));

            return results;
        }

        private List<TestResult> Run(string testName, List<Tuple<byte[], uint>> tests, CRC32 instance)
        {
            List<TestResult> results = new List<TestResult>();

            foreach (var t in tests)
            {
                instance.Reset();
                instance.Process(t.Item1);

                var result = instance.Result();

                var tres = new TestResult(testName, result == t.Item2);

                results.Add(tres);
            }

            return results;
        }

        static List<Tuple<byte[], uint>> CustomizedValues()
        {
            // polynomial = 0x12345678
            // inputReflected = false
            // resultReflected = false
            // initvalue = 0xabcdef12
            // finalxor = 0x9876adcf

            return new List<Tuple<byte[], uint>>()
            {
                Test(new byte[]{ 0x01, 0x02, 0x03, 0x05 },    0xDC273C37  ),
                Test(new byte[]{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39 },     0x5B01ADB7    ),
                Test(System.Text.Encoding.ASCII.GetBytes("QWERASDFZXCV!@#$"),    0x14C44B17  ),
                Test(new byte[0],  0x33BB42DD ),
                Test(new byte[] { 0x01, 0x02, 0x03, 0xdd, 0xee, 0xf1 },    0x1549E17F    )
            };
        }

        static List<Tuple<byte[], uint>> InputReflectedFalse()
        {
            return new List<Tuple<byte[], uint>>()
            {
                Test(new byte[]{ 0x01, 0x02, 0x03, 0x05 },   0xA1AB9041 ),
                Test(new byte[]{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39 },    0x1898913F   ),
                Test(System.Text.Encoding.ASCII.GetBytes("QWERASDFZXCV!@#$"),   0x8BEF70D9 ),
                Test(new byte[0], 0),
                Test(new byte[] { 0x01, 0x02, 0x03, 0xdd, 0xee, 0xf1 },   0x55BE6345   )
            };
        }

        static List<Tuple<byte[], uint>> DefaultInstanceTests()
        {
            return new List<Tuple<byte[], uint>>()
            {
                Test(new byte[]{ 0x01, 0x02, 0x03, 0x05 },  0xC13BCB5B),
                Test(new byte[]{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39 },   0xCBF43926  ),
                Test(System.Text.Encoding.ASCII.GetBytes("QWERASDFZXCV!@#$"),  0x4360A39F),
                Test(new byte[0], 0),
                Test(new byte[] { 0x01, 0x02, 0x03, 0xdd, 0xee, 0xf1 },  0x9DFD3403  ),
                Test(new byte[]
                {0xdd,0x9b,0xC3,0xE2,0xF1,0x33,0x22,0x11,0xE2,0xE1,
0xdd,0x9b,0xC3,0xE2,0xF1,0x33,0x22,0x11,0xE2,0xE1,
0xdd,0x9b,0xC3,0xE2,0xF1,0x33,0x22,0x11,0xE2,0xE1,
0xdd,0x9b,0xC3,0xE2,0xF1,0x33,0x22,0x11,0xE2,0xE1,
0xdd,0x9b,0xC3,0xE2,0xF1,0x33,0x22,0x11,0xE2,0xE1,
0xdd,0x9b,0xC3,0xE2,0xF1,0x33,0x22,0x11,0xE2,0xE1,
0xdd,0x9b,0xC3,0xE2,0xF1,0x33,0x22,0x11,0xE2,0xE1,0xdd,0x9b,0xC3,0xE2,0xF1,0x33,0x22,0x11,0xE2,0xE1,
0xdd,0x9b,0xC3,0xE2,0xF1,0x33,0x22,0x11,0xE2,0xE1,
                },   0x3125723B  )
            };
        }

        static Tuple<byte[], uint> Test(byte[] input, uint result) => new Tuple<byte[], uint>(input, result);
    }
}
