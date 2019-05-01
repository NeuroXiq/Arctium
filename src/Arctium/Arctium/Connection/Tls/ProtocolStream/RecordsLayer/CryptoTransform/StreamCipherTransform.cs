using System;
using System.Security.Cryptography;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.CryptoTransform
{
    //
    //artifacts. current version uses only null stream cipher
    //this code is unsafe
    class NullStreamCipherTransform : CipherTransform
    {   
        public NullStreamCipherTransform()
        {
            
        }

        public override byte[] Decrypt(byte[] buffer, int offset, int length, ulong seqNumber)
        {
            byte[] identity = new byte[length];
            Array.Copy(buffer, offset, identity, 0, length);

            return identity;
        }

        public override byte[] Encrypt(byte[] buffer, int offset, int length, ulong seqNumber)
        {
            byte[] identity = new byte[length];
            Array.Copy(buffer, offset, identity, 0, length);

            return identity;
        }
    }
}
