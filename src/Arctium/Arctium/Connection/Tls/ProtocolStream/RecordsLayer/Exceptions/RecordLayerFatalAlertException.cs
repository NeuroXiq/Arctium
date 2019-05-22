using Arctium.Connection.Tls.Protocol.AlertProtocol;
using System;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer
{
    ///<summary>Exception in throw when it can be summarized by the alert protocol and was throw by record layer.</summary>
    class RecordLayerFatalAlertException : Exception
    {
        public AlertDescription AlertMessageDescription { get; private set; }

        public RecordLayerFatalAlertException(AlertDescription alertDescription,string message) : base(message)
        {
            AlertMessageDescription = alertDescription;
        }
    }
}
