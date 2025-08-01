using Arctium.Protocol.Tls.Tls12.CryptoConfiguration;

namespace Arctium.Protocol.Tls.Tls12.ProtocolStream.RecordsLayer.RecordsLayer12
{
    class RecordLayer12Params
    {
        public RecordCryptoType RecordCryptoType;
        public byte[] MacKey;
        public byte[] BulkKey;
    }
}
