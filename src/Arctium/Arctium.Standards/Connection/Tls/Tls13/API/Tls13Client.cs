using Arctium.Standards.Connection.Tls.Tls13.Protocol;
using System.IO;

namespace Arctium.Standards.Connection.Tls.Tls13.API
{
    public class Tls13Client
    {
        Tls13ClientContext context;

        public Tls13Client(Tls13ClientContext context)
        {
            context.ThrowIfInvalidState();
            this.context = context;
        }

        public Tls13Stream Connect(Stream rawNetworkStream)
        {
            return Connect(rawNetworkStream, out _);
        }

        public Tls13Stream Connect(Stream rawNetworkStream, out Tls13ClientConnectionInfo connectionInfo)
        {
            var protocol = new Tls13ClientProtocol(rawNetworkStream, context);
            var connectionInfoInternal = protocol.Connect();

            connectionInfo = new Tls13ClientConnectionInfo(connectionInfoInternal);

            return new Tls13ClientStreamInternal(protocol);
        }
    }
}
