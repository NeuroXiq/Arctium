using System;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.CryptoTransform
{
    class BlockCipherTransform : TlsRecordTransform
    {
        public BlockCipherTransform()
        {

        }

        public override byte[] Decrypt(byte[] buffer, int offset, int length)
        {
            throw new NotImplementedException();
        }

        public override byte[] Encrypt(byte[] buffer, int offset, int length)
        {
            throw new NotImplementedException();
        }
    }
}
