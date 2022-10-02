using Arctium.Standards.Connection.Tls.Tls13.Protocol;
using System.IO;

namespace Arctium.Standards.Connection.Tls.Tls13.API
{
    public class Tls13Client
    {
        Tls13ClientContext context;

        public Tls13Client(Tls13ClientContext config)
        {
            this.context = config;
        }

        public Tls13Stream Connect(Stream rawNetworkStream)
        {
            var protocol = new Tls13ClientProtocol(rawNetworkStream, context);
            protocol.Connect();

            return new Tls13ClientStreamInternal(protocol);
        }
    }
}
