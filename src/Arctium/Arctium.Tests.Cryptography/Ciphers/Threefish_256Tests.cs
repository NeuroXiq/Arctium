using System;
using System.Collections.Generic;
using System.Text;
using Arctium.Cryptography.Ciphers.BlockCiphers;
using Arctium.Tests.Core;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Helpers.Binary;

namespace Arctium.Tests.Cryptography.Ciphers
{
    public class Threefish_256Tests
    {
        private class ThreefishTest
        {
            public byte[] Key;
            public byte[] Input;
            public byte[] Tweak;
            public byte[] ExpectedOutput;
        }

        public static TestResult[] Run()
        {
            ThreefishTest[] tests = ThreefishTests();
            List<TestResult> results = new List<TestResult>();
            byte[] output = new byte[32];
            int i = 0;

            foreach(ThreefishTest test in tests)
            {
                i++;
                Threefish_256 threefish = new Threefish_256(test.Key);
                threefish.Encrypt(test.Input, 0, output, 0, test.Tweak);
                results.Add(new TestResult()
                        {
                            Name = string.Format("Threefish_256 / {0}", i),
                            Success = MemOps.Memcmp(output, test.ExpectedOutput)
                        });
            }

            return results.ToArray();
        }

        private static ThreefishTest[] ThreefishTests()
        {
            return new ThreefishTest[]
            {
                new ThreefishTest()
                {
                    Key = new byte[32],
                    Input = new byte[32],
                    Tweak = new byte[16],
                    ExpectedOutput = BinConverter.FromString("84DA2A1F8BEAEE947066AE3E3103F1AD536DB1F4A1192495116B9F3CE6133FD8")
                }
            };
        }
    }
}
