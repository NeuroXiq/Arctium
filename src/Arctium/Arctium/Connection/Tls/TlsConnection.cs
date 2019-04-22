using Arctium.Connection.Tls.Operator;
using System;
using System.IO;

namespace Arctium.Connection.Tls
{
    public class TlsConnection
    {
        private Stream innerStream;

        public TlsConnection(Stream innerStream)
        {
            this.innerStream = innerStream;
        }

        ///<summary>Establish new connection on specified stream</summary>
        public TlsStream Connect()
        {
            throw new NotSupportedException("Connection is not supported");
        }

        ///<summary>Accept new connection from specified stream</summary>
        public TlsStream Accept()
        {
            TlsProtocolOperator protocolOperator = TlsProtocolOperator.CreateServerSession(innerStream);
            protocolOperator.Handshake();

            return new TlsStream(protocolOperator);
        }
    }
}
