using Arctium.Connection.Tls.Protocol.RecordProtocol;
using System.IO;

namespace Arctium.Connection.Tls.Buffers
{
    ///<summary>This class facilitate work with tls records</summary>
    class RecordsBuffer
    {
        public struct RecordCursor
        {
            public RecordHeader Header;
            public int RecordOffset;
        }

        public byte[] DataBuffer { get; private set; }
        public RecordCursor Cursor { get; private set; }

        public RecordsBuffer()
        {

        }

        public void GoToNextRecord(Stream readStream)
        {
            
        }
    }
}
