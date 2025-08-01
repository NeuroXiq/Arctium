using Arctium.Protocol.Tls.Protocol.RecordProtocol.Enum;

namespace Arctium.Protocol.Tls.Protocol.RecordProtocol
{
    struct RecordHeader
    {
        public ContentType ContentType;
        public ProtocolVersion Version;
        public int FragmentLength;

        public RecordHeader(ContentType type, ProtocolVersion version, int length)
        {
            ContentType = type;
            Version = version;
            FragmentLength = length;
        }
    }
}
