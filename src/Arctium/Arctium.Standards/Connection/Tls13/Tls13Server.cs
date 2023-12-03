using Arctium.Standards.Connection.Tls13Impl.Protocol;
using System;
using System.IO;

namespace Arctium.Standards.Connection.Tls13
{
    public class Tls13Server
    {
        private Tls13ServerContext serverContext;

        public Tls13Server(Tls13ServerContext ctx)
        {
            serverContext = ctx;
        }

        public Tls13ServerStream Accept(Stream networkStream, out Tls13ServerConnectionInfo connectionInfo)
        {
            connectionInfo = null;
            var instanceContext = new Tls13ServerProtocolInstanceContext(Guid.NewGuid().ToByteArray(), serverContext.Config);
            var protocol = new Tls13ServerProtocol(networkStream, instanceContext);
            var conInfo = protocol.Listen();
            connectionInfo = new Tls13ServerConnectionInfo(conInfo);

            return new Tls13ServerStreamInternal(protocol);
        }

        public Tls13ServerStream Accept(Stream networkStream)
        {
            return Accept(networkStream, out _);
        }

        public void Close()
        {
        }
    }
}
