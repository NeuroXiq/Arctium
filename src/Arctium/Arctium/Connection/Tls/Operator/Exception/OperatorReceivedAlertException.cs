using Arctium.Connection.Tls.Protocol.AlertProtocol;
using System;

namespace Arctium.Connection.Tls.Operator
{
    ///<summary>Exception if throw when received alert message</summary>
    class OperatorReceivedAlertException : Exception
    {
        public AlertDescription AlertDescription;
        public AlertLevel AlertLevel;

        public OperatorReceivedAlertException(AlertLevel level, AlertDescription alertDescription, string message) : base(message)
        {
            AlertDescription = alertDescription;
            AlertLevel = level;
        }
    }
}
