using Arctium.Protocol.Tls.Protocol;

namespace Arctium.Protocol.Tls.ProtocolStream.RecordsLayer.RecordsLayer12
{
    class RecordLayer12Params
    {
        public RecordCryptoType RecordCryptoType;
        public byte[] MacKey;
        public byte[] BulkKey;
    }
}
