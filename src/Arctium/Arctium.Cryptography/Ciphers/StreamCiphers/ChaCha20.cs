using Arctium.Cryptography.Ciphers.StreamCiphers.Algorithms;
using Arctium.Shared.Helpers;
using Arctium.Shared.Other;
using System;

namespace Arctium.Cryptography.Ciphers.StreamCiphers
{
    public class ChaCha20 : StreamCipherBase
    {
        const int InitialCounter = 1;
        const int BlockSize64 = 64;
        
        ChaCha20Algorithm.Context context;
        byte[] temp;
        byte[] zero64bytes;
        int tempLength;
        uint counter;
        byte[] nonce;

        public ChaCha20(byte[] key, byte[] nonce) : base(key)
        {
            Validation.Length(key, 32, nameof(key));
            Validation.Length(nonce, 12, nameof(nonce));

            context = ChaCha20Algorithm.Initialize(key, nonce);
            temp = new byte[BlockSize64];
            zero64bytes = new byte[BlockSize64];
            tempLength = 0;
            this.nonce = nonce;
            Reset();
        }

        public void Reset() => Reset(nonce, InitialCounter);

        public void Reset(byte[] nonce, uint counter)
        {
            this.counter = counter;
            this.nonce = nonce;
            tempLength = 0;
            MemOps.MemsetZero(temp);

            ChaCha20Algorithm.Reset(context, this.key, nonce);
        }

        public override long Decrypt(byte[] inputBuffer, long inputOffset, byte[] outputBuffer, long outputOffset, long length)
        {
            return Encrypt(inputBuffer, inputOffset, outputBuffer, outputOffset, length);
        }

        public override long Encrypt(byte[] inputBuffer, long inputOffset, byte[] outputBuffer, long outputOffset, long length)
        {
            if (length == 0) return 0;

            long io = inputOffset, oo = outputOffset;
            long toEncrypt = length;

            for (; tempLength > 0 && toEncrypt > 0; tempLength--)
            {
                outputBuffer[oo] = (byte)(inputBuffer[io] ^ temp[BlockSize64 - tempLength]);
                toEncrypt--;
                oo++;
                io++;
            }

            long fullBlocks = (toEncrypt / BlockSize64) * BlockSize64;

            for (int i = 0; i < fullBlocks; i += BlockSize64, io += BlockSize64, oo += BlockSize64)
            {
                ChaCha20Algorithm.Encrypt(context, inputBuffer, io, fullBlocks, outputBuffer, oo, counter);
                counter++;
            }

            toEncrypt -= fullBlocks;

            if (toEncrypt > 0)
            {
                // not 64 byte blocks, pretend that this is stream cipher
                // and store full block in temp and xor it with remaining bytes
                MemOps.MemsetZero(temp);
                ChaCha20Algorithm.Encrypt(context, zero64bytes, 0, BlockSize64, temp, 0, counter);
                counter++;
                tempLength = BlockSize64;

                // recursion only once to invoke first loop to xor with temp
                Encrypt(inputBuffer, io, outputBuffer, oo, toEncrypt);
            }

            return length;
        }
    }
}
