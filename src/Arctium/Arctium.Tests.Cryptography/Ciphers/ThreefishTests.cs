using System.Collections.Generic;
using Arctium.Cryptography.Ciphers.BlockCiphers;
using Arctium.Tests.Core;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Helpers.Binary;

namespace Arctium.Tests.Cryptography.Ciphers
{
    public class ThreefishTests
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
            ThreefishTest[] tests256 = ThreefishTests256();
            ThreefishTest[] tests512 = ThreefishTests512();
            ThreefishTest[] tests1024 = ThreefishTests1024();

            List<TestResult> results = new List<TestResult>();
            byte[] output = new byte[32];
            int i = 0;

            foreach(ThreefishTest test in tests256)
            {
                i++;
                Threefish_256 threefish = new Threefish_256(test.Key);
                threefish.Encrypt(test.Input, 0, output, 0, test.Tweak);
                
                results.Add(new TestResult()
                        {
                            Name = string.Format("Threefish_256 / Encrypt / {0}", i),
                            Success = MemOps.Memcmp(output, test.ExpectedOutput)
                        });
                
                threefish.Decrypt(test.ExpectedOutput, 0, output, 0, test.Tweak);

            }

            byte[] output512 = new byte[64];
            i = 0;
            foreach(ThreefishTest test in tests512)
            {
                i++;
                Threefish_512 threefish = new Threefish_512(test.Key);
                threefish.Encrypt(test.Input, 0, output512, 0, test.Tweak);

                results.Add(new TestResult()
                        {
                           Name = string.Format("Threefish_512 / Encrypt / {0}", i),
                           Success = MemOps.Memcmp(output512, test.ExpectedOutput)
                        });

                threefish.Decrypt(test.ExpectedOutput, 0, output512, 0, test.Tweak);
                results.Add(new TestResult()
                        {
                           Name = string.Format("Threefish_512 / Decrypt / {0}", i),
                           Success = MemOps.Memcmp(output512, test.Input)
                        });
            }

            return results.ToArray();
        }

        private static ThreefishTest[] ThreefishTests512()
        {
            return new ThreefishTest[]
            {
                new ThreefishTest()
                {
                    Key = new byte[64],
                    Input = new byte[64],
                    Tweak = new byte[16],
                    ExpectedOutput = BinConverter.FromString("B1A2BBC6EF6025BC40EB3822161F36E375D1BB0AEE3186FBD19E47C5D479947B7BC2F8586E35F0CFF7E7F03084B0B7B1F1AB3961A580A3E97EB41EA14A6D7BBE")
                },
                new ThreefishTest()
                {
                    Key = BinConverter.FromString("101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F"),
                    Input = BinConverter.FromString("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0"),
                    Tweak = BinConverter.FromString("000102030405060708090A0B0C0D0E0F"),
                    ExpectedOutput = BinConverter.FromString("E304439626D45A2CB401CAD8D636249A6338330EB06D45DD8B36B90E97254779272A0A8D99463504784420EA18C9A725AF11DFFEA10162348927673D5C1CAF3D") 
                }
            };
        }


        private static ThreefishTest[] ThreefishTests1024()
        {
            return new ThreefishTest[0];
        }

        private static ThreefishTest[] ThreefishTests256()
        {
            return new ThreefishTest[]
            {
                new ThreefishTest()
                {
                    Key = new byte[32],
                    Input = new byte[32],
                    Tweak = new byte[16],
                    ExpectedOutput = BinConverter.FromString("84DA2A1F8BEAEE947066AE3E3103F1AD536DB1F4A1192495116B9F3CE6133FD8")
                },
                new ThreefishTest()
                {
                    Key = BinConverter.FromString("101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F"),
                    Input = BinConverter.FromString("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0"),
                    Tweak = BinConverter.FromString("000102030405060708090A0B0C0D0E0F"),
                    ExpectedOutput = BinConverter.FromString("E0D091FF0EEA8FDFC98192E62ED80AD59D865D08588DF476657056B5955E97DF") 
                }
            };
        }
    }
}
