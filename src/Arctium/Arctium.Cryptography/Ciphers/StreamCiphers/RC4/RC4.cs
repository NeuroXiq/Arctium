using System;
using System.IO;

namespace Arctium.Cryptography.Ciphers.StreamCiphers.RC4
{
    class RC4 : StreamCipherBase
    {
        public RC4(byte[] key) : base(key)
        {
        }

        public override int Decrypt(byte[] inputBuffer, int inputOffset, int length, byte[] outputBuffer, int outputOffset)
        {
            throw new NotImplementedException();
        }

        public override int Decrypt(Stream inputStream, Stream outputStream)
        {
            throw new NotImplementedException();
        }

        public override int Encrypt(byte[] inputBuffer, int inputOffset, int length, byte[] outputBuffer, int outputOffset)
        {
            throw new NotImplementedException();
        }

        public override int Encrypt(Stream inputStream, Stream outputStream)
        {
            throw new NotImplementedException();
        }
    }
}
