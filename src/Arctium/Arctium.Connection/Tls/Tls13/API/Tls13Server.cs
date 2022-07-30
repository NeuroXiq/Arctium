using Arctium.Connection.Tls.Tls13.Protocol;
using System.IO;

namespace Arctium.Connection.Tls.Tls13.API
{
    public class Tls13Server
    {
        private Stream stream;
        private Tls13ServerConfig config;
        private Tls13Protocol protocol;

        public Tls13Server(Stream stream) : this(stream, Tls13ServerConfig.Default)
        { }

        public Tls13Server(Stream stream, Tls13ServerConfig config)
        {
            this.stream = stream;
            this.config = config;
            this.protocol = new Tls13Protocol(stream);
        }

        public Tls13Stream Open()
        {
            this.protocol.OpenServer();

            return new Tls13StreamInternal(this.protocol);
        }

        public void Close()
        {
        }
    }
}
