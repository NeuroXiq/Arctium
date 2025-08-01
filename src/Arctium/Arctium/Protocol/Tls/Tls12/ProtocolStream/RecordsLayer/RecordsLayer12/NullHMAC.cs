using System.Security.Cryptography;

namespace Arctium.Protocol.Tls.Tls12.ProtocolStream.RecordsLayer.RecordsLayer12
{
    class NullHMAC : HMAC
    {
        public NullHMAC()
        {
            HashSizeValue = 0;
            HashName = "NULL";
            BlockSizeValue = 1;

        }

        protected override void HashCore(byte[] rgb, int ib, int cb)
        {

        }

        protected override byte[] HashFinal()
        {
            return new byte[0];
        }
    }
}
