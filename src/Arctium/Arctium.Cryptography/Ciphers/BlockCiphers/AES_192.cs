using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Cryptography.Ciphers.BlockCiphers
{
    public class AES_192 : AES
    {
        public AES_192(byte[] key, BlockCipherMode mode) : base (key, 128, mode) { }


        public override long Encrypt(byte[] input, long offset, byte[] output, long outputOffset, long length)
        {
            return 0;
        }


        public override long Decrypt(byte[] input, long offset, byte[] output, long outputOffset, long length)
        {
            return 0;
        }
    }
}
