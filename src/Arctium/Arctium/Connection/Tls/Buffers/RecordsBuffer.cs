using Arctium.Connection.Tls.Protocol.RecordProtocol;
using System;

namespace Arctium.Connection.Tls.Buffers
{
    ///<summary>This class facilitate work with tls records</summary>
    class RecordsBuffer
    {
        public struct RecordCursor
        {
            public int RecordOffset;
        }

        public byte[] DataBuffer { get; private set; }
        public RecordCursor Cursor { get; private set; }

        public RecordsBuffer()
        {

        }

        public void EnsureRecord() { }

        public void MoveCursor() { }

    }
}
