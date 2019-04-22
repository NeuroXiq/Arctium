using System;

namespace Arctium.Connection.Tls.BinaryOps.Parser
{
    class RecordParserException : Exception
    {
        public RecordParserException(string message) : base(message)
        {
        }
    }
}
