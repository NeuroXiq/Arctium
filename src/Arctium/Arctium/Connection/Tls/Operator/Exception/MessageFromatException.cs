using System;

namespace Arctium.Connection.Tls.Operator
{
    class MessageFromatException : Exception
    {
        public MessageFromatException(string message) : base(message)
        {
        }
    }
}
