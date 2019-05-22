using Arctium.Connection.Tls.Configuration;
using Arctium.Connection.Tls.Operator;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace Arctium.Connection.Tls
{
    public class TlsServerConnection
    {
        TlsServerConfig config;

        public TlsServerConnection(X509Certificate2 cert)
        {
            //this.config = DefaultConfigurations.CreateDefaultTls12ServerConfig();
            //config.Tls11ServerConfig.
        }

        ///<summary>Accept new connection from specified stream</summary>
        public TlsConnectionResult Accept(Stream innerStream)
        {
            return TlsProtocolOperatorSwitch.OpenServerSession(innerStream, config);

        }
    }
}
