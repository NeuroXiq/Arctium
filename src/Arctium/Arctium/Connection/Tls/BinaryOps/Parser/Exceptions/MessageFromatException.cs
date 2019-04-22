using System;

namespace Arctium.Connection.Tls.BinaryOps.Parser
{
    class MessageFromatException : Exception
    {
        public MessageFromatException(string message) : base(message)
        {
        }
    }
}
