using Arctium.Connection.Tls.Protocol.RecordProtocol;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12
{
    struct RecordData
    {
        public ulong SeqNum;
        public byte[] Buffer;
        public int FragmentOffset;
        public RecordHeader Header;
    }
}
