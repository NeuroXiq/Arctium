using System;

namespace Arctium.Standards.Connection.Tls.Protocol.BinaryOps.Builder
{
    class MessageFromatException : Exception
    {
        public MessageFromatException(string message) : base(message)
        {
        }
    }
}
