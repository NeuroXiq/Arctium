using System;

namespace Arctium.Connection.Tls.Operator
{
    class HandshakeException : Exception
    {
        public HandshakeException(string message) : base(message)
        {
        }
    }
}
