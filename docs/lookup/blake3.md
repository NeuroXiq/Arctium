```cs
using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Shared.Helpers.Buffers;
using System;
using System.Text;

namespace DEBUG_ConsoleApplicationForTests
{
    class Program
    {
        static void Main()
        {
            // Create new instance of blake3 
            Blake3 blake3 = new Blake3();
            
            // Some example data to hash
            byte[] data = Encoding.ASCII.GetBytes("Hello BLAKE3");

            // Hash this bytes
            blake3.HashBytes(data);
            byte[] result = blake3.HashFinal();

            // Show bytes to console
            MemDump.HexDump(result);

            // Generate all test vectors for BLAKE3 (given by authors)
            ShowBlake3TestVectors();

            // OUTPUT:
            // C8E1E720 AD461B2A 1527D6DB E60808CF
            // 91DEBEFE 8DFA7D38 A17C55E9 2DA1C199
            //
            // [And all lines for test vectors, ignored for the sake of readability]
        }

        static void ShowBlake3TestVectors()
        {
            // This method generates all BLAKE3 test vectors from 

            int[] inputSizes = new int[]
            {
                0,1,1023,1024,1025,2048,2049,3072,3073,4096,4097,
                5120,5121,6144,6145,7168,7169,8192,8193,16384,31744,102400
            };

            Blake3 blake3 = new Blake3();

            for (int i = 0; i < inputSizes.Length; i++)
            {
                int len = inputSizes[i];
                byte[] input = new byte[len];
                for (int j = 0; j < len; j++) input[j] = (byte)(j % 251);


                blake3.HashBytes(input);
                byte[] hashed = blake3.HashFinal();

                Console.WriteLine("input_len: {0}", len);
                Console.Write("Hash:");
                MemDump.HexDump(hashed, 32, 1, "");

                blake3.ResetState();
            }
        }
    }
}


```