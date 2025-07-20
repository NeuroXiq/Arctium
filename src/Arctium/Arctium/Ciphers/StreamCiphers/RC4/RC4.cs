using System;
using System.IO;

namespace Arctium.Cryptography.Ciphers.StreamCiphers.RC4
{
    class RC4 : StreamCipherBase
    {
        public RC4(byte[] key) : base(key)
        {
        }

        public override long Decrypt(byte[] inputBuffer, long inputOffset, byte[] outputBuffer, long outputOffset, long length)
        {
            throw new NotImplementedException();
        }

        public override long Encrypt(byte[] inputBuffer, long inputOffset, byte[] outputBuffer, long outputOffset, long length)
        {
            throw new NotImplementedException();
        }
    }
}
