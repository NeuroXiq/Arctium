using Arctium.Connection.Tls.Configuration;
using Arctium.Connection.Tls.Operator;
using System.IO;

namespace Arctium.Connection.Tls
{
    public class TlsServerConnection
    {
        TlsServerConfig config;

        public TlsServerConnection(TlsServerConfig config)
        {
            this.config = config;
        }

   

        ///<summary>Accept new connection from specified stream</summary>
        public TlsStream Accept(Stream innerStream)
        {

            var protocolOperator = TlsProtocolOperatorSwitch.OpenServerSession(innerStream, config);

            return new TlsStream(protocolOperator);
        }
    }
}
