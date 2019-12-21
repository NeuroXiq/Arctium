using System;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Builder
{
    class MessageFromatException : Exception
    {
        public MessageFromatException(string message) : base(message)
        {
        }
    }
}
