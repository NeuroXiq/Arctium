using Arctium.Connection.Tls.Protocol.AlertProtocol;
using System;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer
{
    ///<summary>Exception in throw when it can be summarized by the alert protocol and was throw by record layer.</summary>
    class RecordLayerAlertException : Exception
    {
        public AlertDescription AlertMessageDescription { get; private set; }

        public RecordLayerAlertException(AlertDescription alertDescription,string message) : base(message)
        {
            AlertMessageDescription = alertDescription;
        }
    }
}
