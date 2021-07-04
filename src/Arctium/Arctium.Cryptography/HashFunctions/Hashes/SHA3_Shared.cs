using Arctium.Cryptography.HashFunctions.Hashes.Exceptions;
using Arctium.Shared.Helpers.Binary;
using System;

namespace Arctium.Cryptography.HashFunctions.Hashes
{
    //TODO SHA3 Force inline, maybe unwind all loops
    unsafe class SHA3_Shared
    {

        //
        // This fields represents precomputed results of a Iota RC LFSR function for specific round 
        // means that RC result for round index 0 = array[0] round index 1 =  array[1] 
        // values to xor with line(1) 
        private static readonly ulong[] RCIotaResults = new ulong[]
            {
                0x0000000000000001,
                0x0000000000008082,
                0x800000000000808A,
                0x8000000080008000,
                0x000000000000808B,
                0x0000000080000001,
                0x8000000080008081,
                0x8000000000008009,
                0x000000000000008A,
                0x0000000000000088,
                0x0000000080008009,
                0x000000008000000A,
                0x000000008000808B,
                0x800000000000008B,
                0x8000000000008089,
                0x8000000000008003,
                0x8000000000008002,
                0x8000000000000080,
                0x000000000000800A,
                0x800000008000000A,
                0x8000000080008081,
                0x8000000000008080,
                0x0000000080000001,
                0x8000000080008008,
            };

        // buffers used in computing intermediated states in keccak-p 
        ulong[] keccakBuffer0;
        ulong[] keccakBuffer1;

        ulong[] xoredColumns = new ulong[5];

        private int r;
        public SHA3_Shared(int r)
        {
            this.r = r;
            keccakBuffer0 = new ulong[25];
            keccakBuffer1 = new ulong[25];
        }

        /// <summary>
        /// Processe main hash computation based on keccak-p function.
        /// Stores result in internal state (keccakBuffer0). Length must match input block length based on 'r'.
        /// Can be called multiple times, used by SHA3 Hash function and SHAKE XOF functions.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="offset"></param>
        /// <param name="length"></param>
        public void MainHashComputation(byte* input, long length)
        {
            if (length % (r / 8) != 0 || length <= 0 || length % (r/8) != 0) throw new HashFunctionsExceptionInternal("SHA3 invalid r/length","","STATIC_SHA3_Shared");
            int inputBytesCount = r / 8;
            for (long i = 0; i < length; i += inputBytesCount)
            {
                PrepareKeccakBuffer0(input, i);

                Keccakp();
            }
        }

        /// <summary>
        /// after 'MainHashComputation' keccak-p is invoked without data, used by shake functions
        /// </summary>
        public void Shake_GenerateNextState()
        {
            Keccakp();
        }

        internal void ResetState()
        {
            for (int i = 0; i < 25; i++)
            {
                keccakBuffer0[i] = 0;
                keccakBuffer1[i] = 0;
            }
        }

        // keccakp input is fixed-length bytes from the input message with some zero padded bits based on r
        // called by hash functions
        void PrepareKeccakBuffer0(byte* buffer, long offset)
        {
            int ulongToInsert = r / 64;
            long currentBlockOffset = offset;

            for (int i = 0; i < ulongToInsert; i++)
            {
                keccakBuffer0[i] ^= BinConverter.ToULongLE(buffer + currentBlockOffset);

                currentBlockOffset += 8;
            }
        }

        private void Keccakp()
        {
            ulong[] swap;
            for (int i = 0; i < 24; i++)
            {
                Theta(keccakBuffer0, keccakBuffer1);
                Rho(keccakBuffer1, keccakBuffer0);
                Pi(keccakBuffer0, keccakBuffer1);
                Chi(keccakBuffer1, keccakBuffer0);
                Iota(keccakBuffer0, keccakBuffer1, i);

                swap = keccakBuffer1;
                keccakBuffer1 = keccakBuffer0;
                keccakBuffer0 = swap;
            }   
        }



        // todo rewrite methods to inline variants
        
        /// <summary>
        /// buffer = 200 bytes
        /// </summary>
        /// <param name="outputBuffer"></param>
        /// <param name="offset"></param>
        public void GetCurrentState(byte[] outputBuffer, long offset, int length)
        {
            int bytesCount = length;

            for (int i = 0; i < bytesCount; i++)
            {
                int ulongNo = i / 8;
                int byteNo = i % 8;

                outputBuffer[i] = (byte)((keccakBuffer0[ulongNo] >> (8 * byteNo)) & (ulong)0xff);
            }
        }

        /// <summary>
        /// Creates padding for Hash function.
        /// </summary>
        /// <param name="r"></param>
        /// <param name="messageLengthInBytes"></param>
        /// <returns></returns>
        public byte[] SHA3_GetLastBlockWithPad_HashFunction(long messageLengthInBytes)
        {
            int bytesR = r / 8;

            int padLen = bytesR - ((int)(messageLengthInBytes % bytesR));

            if (padLen < 1) padLen += bytesR;

            byte[] padding = new byte[padLen];

            if (padLen == 1)
            {
                padding[0] = 0x86;
            }
            else
            {
                padding[0] = 0x06; // to message is appended { 01 } bits + padding { 1 [0...] 1 }
                padding[padLen - 1] = 0x80;//0x80; 
            }
                
            return padding;
        }

        public byte[] SHA3_GetLastBlockWidthPad_ShakeFunctions(long messageLengthInBytes)
        {
            int bytesR = r / 8;

            int padLen = (int)(bytesR - (messageLengthInBytes % bytesR));

            if (padLen == 0) padLen += bytesR;

            byte[] padding = new byte[padLen];
            padding[0] = 0x1F;
            padding[padLen - 1] = 0x80;

            return padding;
        }

        static void Iota(ulong[] state, ulong[] outState, int roundIndex)
        {
            for (int i = 0; i < 25; i++) outState[i] = state[i];
            outState[0] ^= RCIotaResults[roundIndex];
        }

        

        static void Chi(ulong[] input, ulong[] output)
        {
            for (int y = 0; y < 5; y++)
            {
                output[(y*5)+ 0] = input[(y*5)+ 0] ^ ((input[(1) + (y * 5)] ^ (~(ulong)0)) & (input[(2) + (y * 5)]));
                output[(y*5)+ 1] = input[(y*5)+ 1] ^ ((input[(2) + (y * 5)] ^ (~(ulong)0)) & (input[(3) + (y * 5)]));
                output[(y*5)+ 2] = input[(y*5)+ 2] ^ ((input[(3) + (y * 5)] ^ (~(ulong)0)) & (input[(4) + (y * 5)]));
                output[(y*5)+ 3] = input[(y*5)+ 3] ^ ((input[(4) + (y * 5)] ^ (~(ulong)0)) & (input[(0) + (y * 5)]));
                output[(y*5)+ 4] = input[(y*5)+ 4] ^ ((input[(0) + (y * 5)] ^ (~(ulong)0)) & (input[(1) + (y * 5)]));
            }
        }   
        
        static void Pi(ulong[] input, ulong[] output)
        {
            for (int x = 0; x < 5; x++)
            {
                for (int y = 0; y < 5; y++)
                {
                    output[x + (5*y)] = input[((x + (3 * y)) % 5) + (x*5)];
                }
            }
        }

        static void Rho(ulong[] input, ulong[] output)
        {
            int x = 1;
            int y = 0;

            output[0] = input[0];

            for (int t = 0; t < 24; t++)
            {
                int n = ((((t + 1) * (t + 2)) / 2)) % 64;

                output[x + (y*5)] = (input[x + (y * 5)] << n) | (input[x + (y * 5)] >> (64 - n));

                int xc = x;
                x = y;
                y = ((2 * xc) + (3 * y)) % 5;
            }
        }

        
        void Theta(ulong[] input, ulong[] output)
        {
            xoredColumns[0] = 0;
            xoredColumns[1] = 0;
            xoredColumns[2] = 0;
            xoredColumns[3] = 0;
            xoredColumns[4] = 0;


            for (int y = 0; y < 5; y++)
            {
                xoredColumns[0] ^= input[4 + (y * 5)] ^ ((input[1 + (y * 5)] << 1) | (input[1 + (y * 5)] >> 63));
                xoredColumns[1] ^= input[0 + (y * 5)] ^ ((input[2 + (y * 5)] << 1) | (input[2 + (y * 5)] >> 63));
                xoredColumns[2] ^= input[1 + (y * 5)] ^ ((input[3 + (y * 5)] << 1) | (input[3 + (y * 5)] >> 63));
                xoredColumns[3] ^= input[2 + (y * 5)] ^ ((input[4 + (y * 5)] << 1) | (input[4 + (y * 5)] >> 63));
                xoredColumns[4] ^= input[3 + (y * 5)] ^ ((input[0 + (y * 5)] << 1) | (input[0 + (y * 5)] >> 63));
            }

            for (int y = 0; y < 5; y++)
            {
                output[0 + (y * 5)] = input[0 + (y * 5)] ^ xoredColumns[0];
                output[1 + (y * 5)] = input[1 + (y * 5)] ^ xoredColumns[1];
                output[2 + (y * 5)] = input[2 + (y * 5)] ^ xoredColumns[2];
                output[3 + (y * 5)] = input[3 + (y * 5)] ^ xoredColumns[3];
                output[4 + (y * 5)] = input[4 + (y * 5)] ^ xoredColumns[4];
            }
        }



        ///
        /// OBSOLETED but work
        ///

        static void Iota_OBSOLETE(ulong[] state, ulong[] outState, int roundIndex)
        {
            ulong r = 0;

            r |= (rc(0 + (7 * roundIndex)) << 0);
            r |= (rc(1 + (7 * roundIndex)) << 1);
            r |= (rc(2 + (7 * roundIndex)) << 3);
            r |= (rc(3 + (7 * roundIndex)) << 7);
            r |= (rc(4 + (7 * roundIndex)) << 15);
            r |= (rc(5 + (7 * roundIndex)) << 31);
            r |= (rc(6 + (7 * roundIndex)) << 63);

            for (int i = 0; i < 25; i++) outState[i] = state[i];
            outState[0] ^= RCIotaResults[roundIndex];
        }

        static ulong rc(int t)
        {
            if (t % 255 == 0) return 1;

            uint r = 0x80;
            uint bitsClear = ~((uint)((1 << 8) | (1 << 4) | (1 << 3) | (1 << 2)));
            uint nextBitsState = 0;

            for (int i = 1; i <= t % 255; i++)
            {
                nextBitsState =
                    ((((r >> 8) ^ r) & 1) << 8) |
                    ((((r >> 4) ^ r) & 1) << 4) |
                    ((((r >> 3) ^ r) & 1) << 3) |
                    ((((r >> 2) ^ r) & 1) << 2);

                r &= bitsClear;
                r |= nextBitsState;
                r >>= 1;
            }

            return ((ulong)(r & 0x80) >> 7);
        }
    }
}
