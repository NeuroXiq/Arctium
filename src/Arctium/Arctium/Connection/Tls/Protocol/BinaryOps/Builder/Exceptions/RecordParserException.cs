using System;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Builder
{
    class RecordParserException : Exception
    {
        public RecordParserException(string message) : base(message)
        {
        }
    }
}
