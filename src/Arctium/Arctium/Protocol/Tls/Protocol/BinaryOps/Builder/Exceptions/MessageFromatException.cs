using System;

namespace Arctium.Protocol.Tls.Protocol.BinaryOps.Builder
{
    class MessageFromatException : Exception
    {
        public MessageFromatException(string message) : base(message)
        {
        }
    }
}
