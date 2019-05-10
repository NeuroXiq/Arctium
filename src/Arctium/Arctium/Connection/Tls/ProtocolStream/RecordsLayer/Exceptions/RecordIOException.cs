using System;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer
{
    class RecordIOException : Exception
    {

        public RecordIOException(string message) : base(message)
        {
        }
    }
}
