using Arctium.Standards.Connection.Tls.Tls13.Protocol;
using System.IO;

namespace Arctium.Standards.Connection.Tls.Tls13.API
{
    public class Tls13Client
    {
        Tls13ClientConfig config;

        public Tls13Client(Tls13ClientConfig config)
        {
            this.config = config;
        }

        public Tls13Stream Connect(Stream rawNetworkStream)
        {
            var protocol = new Tls13ClientProtocol(rawNetworkStream, config);
            protocol.Connect();

            return new Tls13ClientStreamInternal(protocol);
        }
    }
}
