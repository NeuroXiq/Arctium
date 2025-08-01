using System;

namespace Arctium.Protocol.Tls.Protocol.BinaryOps.Builder.Exceptions
{
    class MessageFromatException : Exception
    {
        public MessageFromatException(string message) : base(message)
        {
        }
    }
}
