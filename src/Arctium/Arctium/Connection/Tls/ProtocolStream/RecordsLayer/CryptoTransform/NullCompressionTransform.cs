using System;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.CryptoTransform
{
    class NullCompressionTransform : CompressionTransform
    {
        public override byte[] Compress(byte[] buffer, int offset, int length)
        {
            byte[] identity = new byte[length];
            Array.Copy(buffer, offset, identity, 0, length);

            return identity;
        }

        public override byte[] Decompress(byte[] buffer, int offset, int length)
        {
            byte[] identity = new byte[length];
            Array.Copy(buffer, offset, identity, 0, length);

            return identity;
        }
    }
}
