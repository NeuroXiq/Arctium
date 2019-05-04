using System.Security.Cryptography;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer11.CryptoTransform
{
    class NullHMAC : HMAC
    {
        public NullHMAC()
        {
            base.HashSizeValue = 0;
            base.HashValue = new byte[0];
            base.KeyValue = new byte[0];
        }

        protected override void HashCore(byte[] rgb, int ib, int cb)
        {
            
        }

        public override byte[] Hash
        {
            get
            {
                return new byte[0];
            }
        }

        public override int OutputBlockSize
        {
            get
            {
                return 0;
            }
        }
    }
}
