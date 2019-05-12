using Arctium.Connection.Tls.Protocol.AlertProtocol;
using System;

namespace Arctium.Connection.Tls.Operator
{
    class TlsProtocolOperatorAlertException : Exception
    {
        public AlertDescription AlertMessageDescription;

        public TlsProtocolOperatorAlertException(AlertDescription description, string message) : base(message)
        {
            this.AlertMessageDescription = description;
        }
    }
}
