using System;

namespace Arctium.Protocol.Tls13
{
    public class ServerProtocolContext
    {
        /// <summary>
        /// Unique identifier for current instance of server protocol
        /// (connected with single client, can also be interpreted as client unique id)
        /// </summary>
        public ReadOnlyMemory<byte> Id { get; private set; }
    }
}
