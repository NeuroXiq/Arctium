using Arctium.Standards.Connection.Tls.Tls13.Protocol;
using System.IO;

namespace Arctium.Standards.Connection.Tls.Tls13.API
{
    public class Tls13Server
    {
        private Stream stream;
        private Tls13ServerContext serverContext;

        // private Tls13Protocol protocol;
        Tls13ServerProtocol protocol;
        // Tls13Protocol protocol;

        public Tls13Server(Tls13ServerContext ctx)
        {
            this.serverContext = ctx;
        }

        public Tls13ServerStream Accept(Stream networkStream, out Tls13ServerConnectionInfo connectionInfo)
        {
            connectionInfo = null;
            var protocol = new Tls13ServerProtocol(networkStream, serverContext);
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
