using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Cryptography.Ciphers.BlockCiphers.Shared
{
    unsafe class ModeOfOperationAlgorithm
    {
        delegate void EncryptionFunctionDelegate(byte* buffer, long inOffset, byte* output, long outOffset, long length);
        EncryptionFunctionDelegate encryptFunc;

        private ModeOfOperationAlgorithm(BlockCipher cipher, BlockCipherMode mode)
        {
            if (mode != BlockCipherMode.ECB) throw new NotSupportedException();
        }
    }
}
