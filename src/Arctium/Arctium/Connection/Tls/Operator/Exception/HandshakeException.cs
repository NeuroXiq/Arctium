using System;

namespace Arctium.Connection.Tls.Crypto
{
    class HandshakeException : Exception
    {
        public HandshakeException(string message) : base(message)
        {
        }
    }
}
