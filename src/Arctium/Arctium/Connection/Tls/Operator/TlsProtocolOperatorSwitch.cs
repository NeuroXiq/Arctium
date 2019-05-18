using Arctium.Connection.Tls.Configuration;
using Arctium.Connection.Tls.Operator.Tls11Operator;
using Arctium.Connection.Tls.Operator.Tls12Operator;
using Arctium.Connection.Tls.Protocol.RecordProtocol;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer;
using System;
using System.IO;

namespace Arctium.Connection.Tls.Operator
{
    class TlsProtocolOperatorSwitch
    {
        public static TlsProtocolOperator OpenServerSession(Stream innerStream, TlsServerConfig serverConfig)
        {
            Tls12ServerOperator o = Tls12ServerOperator.OpenNewSession(null, innerStream);

            o.OpenSession();
            return o;
        }
    }
}