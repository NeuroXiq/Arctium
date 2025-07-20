using System.Security.Cryptography;

namespace Arctium.Standards.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12
{
    class NullHMAC : HMAC
    {
        public NullHMAC()
        {
            base.HashSizeValue = 0;
            base.HashName = "NULL";
            base.BlockSizeValue = 1;
            
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
