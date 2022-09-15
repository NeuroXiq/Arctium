using System;

namespace Arctium.Cryptography.Ciphers.StreamCiphers.Algorithms
{
    public static class ChaCha20Algorithm
    {
        public class Context
        {
            public uint[] State;
            // public byte[] Key;
            // public byte[] Nonce;
            public uint[] WorkingState;
            public byte[] KeyStream;
        }

        public static Context Initialize(byte[] key, byte[] nonce)
        {
            Context c = new Context()
            {
                State = new uint[16],
                //Key = new byte[32],
                //Nonce = new byte[12],
                WorkingState = new uint[16],
                KeyStream = new byte[64]
            };

            // for (int i = 0; i < 32; i++) c.Key[i] = key[i];
            // for (int i = 0; i < 12; i++) c.Nonce[i] = nonce[i];

            Reset(c, key, nonce);

            return c;
        }

        public static void Decrypt(Context context,
            byte[] input,
            long inOffset,
            long length,
            byte[] output,
            long outOffset,
            uint counter)
        {
            ExecuteCrypto(context, input, inOffset, length, output, outOffset, counter);
        }

        static void ExecuteCrypto(Context context,
            byte[] input,
            long inOffset,
            long length,
            byte[] output,
            long outOffset,
            uint counter)
        {
            if (length % 64 != 0) throw new Exception("internal: works only with 64 byte blocks");

            for (int i = 0; i < length; i += 64, counter++)
            {
                // set counter
                context.State[12] = counter;
                Block(context);

                for (int j = 0; j < 64; j++) output[outOffset + j + i] = (byte)(input[inOffset + i + j] ^ context.KeyStream[j]);
            }
        }

        public static void Encrypt(Context context,
            byte[] input,
            long inOffset,
            long length,
            byte[] output,
            long outOffset,
            uint counter)
        {
            ExecuteCrypto(context, input, inOffset, length, output, outOffset, counter);
        }

        public static void Reset(Context context, byte[] key, byte[] nonce)
        {
            uint[] state = context.State;
            byte[] k = key;
            byte[] n = nonce;

            state[0] = 0x61707865;
            state[1] = 0x3320646e;
            state[2] = 0x79622d32;
            state[3] = 0x6b206574;

            for (int i = 0; i < 8; i++)
            {
                state[i + 4] = ((uint)k[(i * 4) + 0] << 0) |
                    ((uint)k[(i * 4) + 1] <<  8) |
                    ((uint)k[(i * 4) + 2] << 16) |
                    ((uint)k[(i * 4) + 3] << 24);
            }

            for (int i = 0; i < 3; i++)
            {
                state[i + 13] = ((uint)n[(i * 4) + 0] << 0) |
                    ((uint)n[(i * 4) + 1] << 8)  |
                    ((uint)n[(i * 4) + 2] << 16) |
                    ((uint)n[(i * 4) + 3] << 24);
            }
        }

        public static void Block(Context c)
        {
            uint[] w = c.WorkingState;

            for (int i = 0; i < 16; i++) c.WorkingState[i] = c.State[i];

            for (int i = 0; i < 10; i++)
            {
                QRound(w, 0, 4, 8, 12);
                QRound(w, 1, 5, 9, 13);
                QRound(w, 2, 6, 10, 14);
                QRound(w, 3, 7, 11, 15);
                QRound(w, 0, 5, 10, 15);
                QRound(w, 1, 6, 11, 12);
                QRound(w, 2, 7, 8, 13);
                QRound(w, 3, 4, 9, 14);
            }

            for (int i = 0; i < 16; i++) c.WorkingState[i] += c.State[i];

            for (int i = 0; i < 16; i++)
            {
                c.KeyStream[(i * 4) + 0] = (byte)((c.WorkingState[i] & 0x000000FF) >> 0);
                c.KeyStream[(i * 4) + 1] = (byte)((c.WorkingState[i] & 0x0000FF00) >> 8);
                c.KeyStream[(i * 4) + 2] = (byte)((c.WorkingState[i] & 0x00FF0000) >> 16);
                c.KeyStream[(i * 4) + 3] = (byte)((c.WorkingState[i] & 0xFF000000) >> 24);
            }
        }

        static void QRound(uint[] workingState, int a, int b, int c, int d)
        {
            uint[] w = workingState;
            w[a] += w[b]; w[d] ^= w[a]; w[d] = ROL(w[d], 16);
            w[c] += w[d]; w[b] ^= w[c]; w[b] = ROL(w[b], 12);
            w[a] += w[b]; w[d] ^= w[a]; w[d] = ROL(w[d], 8);
            w[c] += w[d]; w[b] ^= w[c];  w[b] = ROL(w[b], 7);
        }

        static uint ROL(uint v, int n) { return (v << n) | (v >> (32 - n)); }
    }
}
