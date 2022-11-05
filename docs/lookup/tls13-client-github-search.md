```cs

using Arctium.Cryptography.Ciphers.BlockCiphers.Shared;
using Arctium.Cryptography.Ciphers.BlockCiphers.Twofish;
using Arctium.Shared.Helpers.Buffers;
using System;

namespace DEBUG_ConsoleApplicationForTests
{
    unsafe class Program
    {
        static void Main()
        {
            // Twofish example
            // input block size: 16 bytes
            // key length: 128, 192 or 256 bits
            // supported modes: ECB

            // this example use 192 bit key

            byte[] key = new byte[24];
            byte[] input = new byte[32];
            byte[] output = new byte[32];

            Twofish twofish = new Twofish(key, BlockCipherMode.ECB);

            twofish.Encrypt(input, 0, output, 0, 32);
            
            // Write to console encryption result
            MemDump.HexDump(output, 4, 4);

            // Decrypt to get again zero bytes
            twofish.Decrypt(output, 0, input, 0, 32);

            // Write to console decryption result
            MemDump.HexDump(input, 4, 4);

            /*
             * Console output:
             * EFA71F78 8965BD44 53F86017 8FC19101
             * EFA71F78 8965BD44 53F86017 8FC19101
             * 
             * 00000000 00000000 00000000 00000000
             * 00000000 00000000 00000000 00000000
             * 
             */
			 
			 // Value above can be compared with test vectors for Twofish
			 // https://www.schneier.com/code/ecb_ival.txt
        }

		// [ Implementation of test vectors functions ]

        // this function generates exactly same 
        // output as in the test vectors on schneier.com website,
        // where iteratively each key is replaced with input,
        // and each input is replaced with output


        static void TestVector256()
        {
            byte[] key = new byte[32];
            byte[] input = new byte[16];
            byte[] output = new byte[16];

            for (int i = 0; i < 49; i++)
            {
                // key size exceed input block size,
                // set first 16 bytes as last key bytes
                // and copy input to key

                MemCpy.Copy(key, 0, key, 16, 16);
                MemCpy.Copy(input, 0, key, 0, 16);
                MemCpy.Copy(output, input);

                Twofish twofish = new Twofish(key, BlockCipherMode.ECB);
                twofish.Encrypt(input, 0, output, 0, 16);
                Console.WriteLine("I={0}", i + 1);
                Console.Write("KEY=");
                MemDump.HexDump(key, 32, 32);
                Console.Write("PT=");
                MemDump.HexDump(input, 16, 16);
                Console.Write("CT=");
                MemDump.HexDump(output, 16, 16);
            }
        }

      

        static void TestVector192()
        {
            byte[] key = new byte[24];
            byte[] input = new byte[16];
            byte[] output = new byte[16];

            for (int i = 0; i < 49; i++)
            {
                // key size exceed input block size,
                // set first 8 bytes as last key bytes
                // and copy input to key

                MemCpy.Copy(key, 0, key, 16, 8);
                MemCpy.Copy(input, 0, key, 0, 16);
                MemCpy.Copy(output, input);

                Twofish twofish = new Twofish(key, BlockCipherMode.ECB);
                twofish.Encrypt(input, 0, output, 0, 16);
                Console.WriteLine("I={0}", i + 1);
                Console.Write("KEY=");
                MemDump.HexDump(key, 24, 24);
                Console.Write("PT=");
                MemDump.HexDump(input, 16, 16);
                Console.Write("CT=");
                MemDump.HexDump(output, 16, 16);
            }
        }


        static void TestVector128()
        {
            
            byte[] key = new byte[16];
            byte[] input = new byte[16];
            byte[] output = new byte[16];

            for (int i = 0; i < 49; i++)
            {
                // move input to key
                // and output to input
                MemCpy.Copy(input, key);
                MemCpy.Copy(output, input);

                // initialize cipher

                Twofish twofish = new Twofish(key, BlockCipherMode.ECB);

                // encrypt
                twofish.Encrypt(input, 0, output, 0, 16);

                //hexDump is utility class which writes to console formatted hex values

                Console.WriteLine("I={0}", i + 1);

                Console.Write("KEY=");
                MemDump.HexDump(key, 16, 16);

                Console.Write("PT=");
                MemDump.HexDump(input, 16, 16);

                Console.Write("CT=");
                MemDump.HexDump(output, 16, 16);
            }
        }
    }
}

```