using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders.ExtensionsBuilders
{
    struct ExtensionFormatData
    {
        ///<summary>buffer contains extenion bytes</summary>
        public byte[] Buffer;
        ///<summary>Offset of the extension data (after its type and length)</summary>
        public int DataOffset;
        ///<summary>Expected length of the extension (from bytes before 'DataOffset')</summary>
        public int Length;
        ///<summary>Extensions type (from bytes before 'DataOffset')</summary>
        public HandshakeExtensionType Type;
    }
}
