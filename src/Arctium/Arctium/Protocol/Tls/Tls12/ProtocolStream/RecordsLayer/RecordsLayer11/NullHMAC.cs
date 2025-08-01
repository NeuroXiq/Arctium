using System.Security.Cryptography;

namespace Arctium.Protocol.Tls.Tls12.ProtocolStream.RecordsLayer.RecordsLayer11
{
    class NullHMAC : HMAC
    {
        public NullHMAC()
        {
            HashSizeValue = 0;
            HashValue = new byte[0];
            KeyValue = new byte[0];
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
