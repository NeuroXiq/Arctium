using System;

namespace Arctium.Cryptography.Ciphers.BlockCiphers
{
    internal unsafe class BlockCipherModeHelper
    {
        public delegate void EncryptBlock(byte* input, long inputOffset, byte* output, long outputOffset);

        public BlockCipherModeHelper()
        {

        }
    }
}
