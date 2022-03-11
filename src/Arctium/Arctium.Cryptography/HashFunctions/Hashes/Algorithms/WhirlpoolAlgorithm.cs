using Arctium.Shared.Helpers.Buffers;

namespace Arctium.Cryptography.HashFunctions.Hashes.Algorithms
{
    public static class WhirlpoolAlgorithm
    {
        const long BlockLenBytes = 64;
        const byte GFPoly = 0x1D;

        public class State
        {
            public byte[] H;
            public ulong ProcessedBytes;
        }

        public static void Process512BitBlocks(State state, byte[] buffer, long offset, long length)
        {
            for (long i = offset; i < length + offset; i += BlockLenBytes)
            {
                ProcessBlock(state, buffer, i);
                state.ProcessedBytes += 64;
            }
        }

        public static void ProcessLastBlock(State state, byte[] buffer, long offset, long length)
        {
            byte[] lastBlock;
            ulong lengthInBits = (state.ProcessedBytes + (ulong)length) * 8;

            if (length < 64 - 32 - 1)
            {
                lastBlock = new byte[64];
            }
            else 
            {
                lastBlock = new byte[128];
            }

            lastBlock[length] = 0x80;

            MemMap.ToBytes1ULongBE(lengthInBits, lastBlock, lastBlock.Length - 8);
            MemCpy.Copy(buffer, offset, lastBlock, 0, length);

            Process512BitBlocks(state, lastBlock, 0, lastBlock.Length);
        }

        public static State InitState()
        {
            State state = new State();
            state.H = new byte[64];

            ResetState(state);

            return state;
        }

        public static void GetHash(State state, byte[] outputBuffer, long outputOffset)
        {
            MemCpy.Copy(state.H, 0, outputBuffer, outputOffset, 64);
        }

        public static void ResetState(State state)
        {
            for (int i = 0; i < 64; i++)
            {
                state.H[i] = 0;
            }

            state.ProcessedBytes = 0;
        }

        // Private methods

        private static void ProcessBlock(State state, byte[] buffer, long offset)
        {
            byte[] Hnext = new byte[64];

            W(state.H, buffer, (int)offset, Hnext);

            for (int i = 0; i < 64; i++) Hnext[i] ^= (byte)(state.H[i] ^ buffer[i + offset]);
            
            state.H = Hnext;

            // MemDump.HexDump(state.H);
        }

        private static void W(byte[] K, byte[] input, int inputOffset, byte[] output)
        {
            //MemDump.HexDump(input, 0, 64,1,8);

            byte[] keySchedule = new byte[64 * 11];
            
            for (int i = 0; i < 64; i++) keySchedule[i] = K[i];

            for (int i = 0; i < 10; i++)
            {
                byte[] roundConst = new byte[64];

                for (int j = 0; j < 8; j++) roundConst[j] = S[(8 * (i)) + j];


                RoundFunc(roundConst, 0, keySchedule, (i) * 64, keySchedule, (i+1) * 64);
                //MemDump.HexDump(keySchedule, (i - 1) * 64, 64, 1, 8); 
            }

            byte[] tempOut = new byte[64];
            MemCpy.Copy(input, inputOffset, tempOut, 0, 64);

            for (int i = 0; i < 64; i++) tempOut[i] = (byte)(keySchedule[i] ^ input[inputOffset + i]);

            for (int i = 0; i < 10; i++)
            {
                RoundFunc(keySchedule, (i+1) * 64, tempOut, 0, output, 0);
                // MemDump.HexDump(output, 0, 64, 1,8);

                MemCpy.Copy(output, 0, tempOut, 0, 64);
            }

        }

        static void RoundFunc(byte[] key, int keyOffset, byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
           for (int i = 0; i < 64; i++) output[i + outputOffset] = input[i + inputOffset];

           for (int i = 0; i < 64; i++) output[i + outputOffset] = S[input[i + inputOffset]];

           byte[] shifted = new byte[64];


           for (int i = 0; i < 8; i++)
           {
               for (int j = i; j < 8 + i; j++)
               {
                   shifted[((j * 8) % 64) + i] = output[outputOffset + ((j - i) * 8) + i];
               }
           }


           Theta(shifted, 0, output, outputOffset);

           for (int i = 0; i < 64; i++) output[outputOffset + i] ^= key[i + keyOffset];
        }

        static void Theta(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    byte mul = 0;

                    for (int k = 0; k < 8; k++)
                    {
                        byte a = input[inputOffset + (i * 8) + k];
                        byte b = C[(j) + (k * 8)];
                        byte r = GMul(a, b);
                        mul ^= r;
                    }

                    output[outputOffset + (i * 8) + j] = mul;
                }
            }
        }

        static byte GMul(byte a, byte b)
        {
            byte r = 0;
            byte p = b;

            for (int i = 0; i < 8; i++)
            {
                if ((a & (1 << i)) != 0)
                {
                    r ^= p;
                }

                if ((p & 0x80) != 0)
                {
                    p = (byte)(p << 1);
                    p ^= GFPoly;
                }
                else
                {
                    p <<= 1;
                }
            }

            return r;
        }

        static readonly byte[] S = new byte[]
        {
            0x18, 0x23, 0xc6, 0xE8, 0x87, 0xB8, 0x01, 0x4F, 0x36, 0xA6, 0xd2, 0xF5, 0x79, 0x6F, 0x91, 0x52,
            0x60, 0xBc, 0x9B, 0x8E, 0xA3, 0x0c, 0x7B, 0x35, 0x1d, 0xE0, 0xd7, 0xc2, 0x2E, 0x4B, 0xFE, 0x57,
            0x15, 0x77, 0x37, 0xE5, 0x9F, 0xF0, 0x4A, 0xdA, 0x58, 0xc9, 0x29, 0x0A, 0xB1, 0xA0, 0x6B, 0x85,
            0xBd, 0x5d, 0x10, 0xF4, 0xcB, 0x3E, 0x05, 0x67, 0xE4, 0x27, 0x41, 0x8B, 0xA7, 0x7d, 0x95, 0xd8,
            0xFB, 0xEE, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9E, 0xcA, 0x2d, 0xBF, 0x07, 0xAd, 0x5A, 0x83, 0x33,
            0x63, 0x02, 0xAA, 0x71, 0xc8, 0x19, 0x49, 0xd9, 0xF2, 0xE3, 0x5B, 0x88, 0x9A, 0x26, 0x32, 0xB0,
            0xE9, 0x0F, 0xd5, 0x80, 0xBE, 0xcd, 0x34, 0x48, 0xFF, 0x7A, 0x90, 0x5F, 0x20, 0x68, 0x1A, 0xAE,
            0xB4, 0x54, 0x93, 0x22, 0x64, 0xF1, 0x73, 0x12, 0x40, 0x08, 0xc3, 0xEc, 0xdB, 0xA1, 0x8d, 0x3d,
            0x97, 0x00, 0xcF, 0x2B, 0x76, 0x82, 0xd6, 0x1B, 0xB5, 0xAF, 0x6A, 0x50, 0x45, 0xF3, 0x30, 0xEF,
            0x3F, 0x55, 0xA2, 0xEA, 0x65, 0xBA, 0x2F, 0xc0, 0xdE, 0x1c, 0xFd, 0x4d, 0x92, 0x75, 0x06, 0x8A,
            0xB2, 0xE6, 0x0E, 0x1F, 0x62, 0xd4, 0xA8, 0x96, 0xF9, 0xc5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4c,
            0x5E, 0x78, 0x38, 0x8c, 0xd1, 0xA5, 0xE2, 0x61, 0xB3, 0x21, 0x9c, 0x1E, 0x43, 0xc7, 0xFc, 0x04,
            0x51, 0x99, 0x6d, 0x0d, 0xFA, 0xdF, 0x7E, 0x24, 0x3B, 0xAB, 0xcE, 0x11, 0x8F, 0x4E, 0xB7, 0xEB,
            0x3c, 0x81, 0x94, 0xF7, 0xB9, 0x13, 0x2c, 0xd3, 0xE7, 0x6E, 0xc4, 0x03, 0x56, 0x44, 0x7F, 0xA9,
            0x2A, 0xBB, 0xc1, 0x53, 0xdc, 0x0B, 0x9d, 0x6c, 0x31, 0x74, 0xF6, 0x46, 0xAc, 0x89, 0x14, 0xE1,
            0x16, 0x3A, 0x69, 0x09, 0x70, 0xB6, 0xd0, 0xEd, 0xcc, 0x42, 0x98, 0xA4, 0x28, 0x5c, 0xF8, 0x86,
        };

        static readonly byte[] C = new byte[] 
        {
            0x01, 0x01, 0x04, 0x01, 0x08, 0x05, 0x02, 0x09,
            0x09, 0x01, 0x01, 0x04, 0x01, 0x08, 0x05, 0x02,
            0x02, 0x09, 0x01, 0x01, 0x04, 0x01, 0x08, 0x05,
            0x05, 0x02, 0x09, 0x01, 0x01, 0x04, 0x01, 0x08,
            0x08, 0x05, 0x02, 0x09, 0x01, 0x01, 0x04, 0x01,
            0x01, 0x08, 0x05, 0x02, 0x09, 0x01, 0x01, 0x04,
            0x04, 0x01, 0x08, 0x05, 0x02, 0x09, 0x01, 0x01,
            0x01, 0x04, 0x01, 0x08, 0x05, 0x02, 0x09, 0x01,
        };
    }
}
