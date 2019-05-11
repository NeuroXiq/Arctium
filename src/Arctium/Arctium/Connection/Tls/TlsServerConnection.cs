using Arctium.Connection.Tls.Operator;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace Arctium.Connection.Tls
{
    public class TlsServerConnection
    {   
        public TlsServerConnection(X509Certificate2 x509cert)
        {
        }

   

        ///<summary>Accept new connection from specified stream</summary>
        public TlsStream Accept(Stream innerStream)
        {
            var protocolOperator = TlsProtocolOperatorSwitch.OpenServerSession(innerStream);

            return new TlsStream(protocolOperator);
        }
    }
}
