using Arctium.Connection.Tls.Protocol;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12
{
    class RecordLayer12Params
    {
        public RecordCryptoType RecordCryptoType;
        public byte[] MacKey;
        public byte[] BulkKey;
    }
}
