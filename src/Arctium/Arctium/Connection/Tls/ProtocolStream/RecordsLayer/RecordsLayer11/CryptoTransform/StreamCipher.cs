using System;
using System.Security.Cryptography;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer11.CryptoTransform
{
    //
    //artifacts. current version uses only null stream cipher
    //this code is dangerous
    class NullStreamCipherTransform : Cipher
    {   
        public NullStreamCipherTransform()
        {
            
        }

        public override byte[] EncryptToCiphertextFragment(byte[] buffer, int offset, int length)
        {
            byte[] identity = new byte[length];
            Array.Copy(buffer, offset, identity, 0, length);
            //hmac = new byte[0];

            return identity;
        }

        public override byte[] DecryptToCompressedFragment(byte[] buffer, int offset, int length)
        {
            byte[] identity = new byte[length];
            Array.Copy(buffer, offset, identity, 0, length);
            //hmac = new byte[0];

            return identity;
        }
    }
}
