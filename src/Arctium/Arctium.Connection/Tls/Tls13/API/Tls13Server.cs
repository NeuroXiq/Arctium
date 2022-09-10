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

        public Tls13Server(Stream stream) : this(stream, Tls13ServerConfig.Default)
        {
            // protocol = new Tls13ServerProtocol(stream);
            // protocol = new Tls13Protocol(stream, config);
            throw new System.Exception();
        }

        public Tls13Server(Stream stream, Tls13ServerConfig config)
        {
            this.stream = stream;
            this.config = config;
            // this.protocol = new Tls13Protocol(stream, config);
            protocol = new Tls13ServerProtocol(stream, config);
        }

        public Tls13Stream Open()
        {
            this.protocol.Listen();

            throw new System.Exception();

            // return new Tls13StreamInternal(this.protocol);
        }

        public void Close()
        {
        }
    }
}
