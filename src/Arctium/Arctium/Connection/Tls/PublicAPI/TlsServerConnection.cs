using Arctium.Connection.Tls.Operator;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace Arctium.Connection.Tls
{
    public class TlsServerConnection
    {
        private Stream innerStream;
        
        public TlsServerConnection(Stream innerStream, X509Certificate2 x509cert)
        {
            this.innerStream = innerStream;
        }

        public TlsServerConnection(Stream innerStream, X509Certificate2 cert, TlsType types)
        {

        }

        ///<summary>Accept new connection from specified stream</summary>
        public TlsStream Accept()
        {
            var protocolOperator = TlsProtocolOperatorSwitch.OpenServerSession(innerStream);

            return new TlsStream(protocolOperator);
        }
    }
}
