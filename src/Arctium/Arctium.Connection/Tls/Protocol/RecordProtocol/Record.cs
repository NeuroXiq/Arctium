using Arctium.Connection.Tls.Protocol;

namespace Arctium.Connection.Tls.Protocol.RecordProtocol
{
    class Record
    {
        public ContentType Type;
        public ProtocolVersion Version;
        ///<summary>Fragment length in bytes</summary>
        public ushort Length;
        public byte[] Fragment;
    }
}
