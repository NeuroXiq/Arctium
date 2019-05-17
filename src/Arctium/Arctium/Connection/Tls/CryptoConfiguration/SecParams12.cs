using Arctium.Connection.Tls.CryptoFunctions;
using Arctium.Connection.Tls.Protocol;

namespace Arctium.Connection.Tls.CryptoConfiguration
{
    class SecParams12
    {
        public RecordCryptoType RecordCryptoType;

        public byte[] MasterSecret;

        public byte[] MacWriteSecret;
        public byte[] MacReadSecret;
        public byte[] BulkWriteKey;
        public byte[] BulkReadKey;
        
        //public byte[] WriteIV;
        //public byte[] ReadIV;
    }
}
