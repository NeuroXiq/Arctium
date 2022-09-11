using Arctium.Connection.Tls.Tls13.Protocol;
using System.IO;

namespace Arctium.Connection.Tls.Tls13.API
{
    public class Tls13Server
    {
        private Stream stream;
        private Tls13ServerConfig config;
        // private Tls13Protocol protocol;
        Tls13ServerProtocol protocol;
        // Tls13Protocol protocol;

        public Tls13Server(Tls13ServerConfig config)
        {
            this.config = config;   
        }

        public Tls13Stream Accept(Stream networkStream)
        {
            var protocol = new Tls13ServerProtocol(networkStream, config);
            protocol.Listen();

            return new Tls13ServerStreamInternal(protocol);
        }

        public void Close()
        {
        }
    }
}
