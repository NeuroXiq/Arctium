using Arctium.Standards.Connection.Tls13;
using Arctium.Standards.Connection.Tls13Impl.Model;
using System;

namespace Arctium.Standards.Connection.Tls13Impl.Protocol
{
    internal class Tls13ReceivedAlertException : Tls13AlertException
    {
        public Tls13ReceivedAlertException(AlertLevel level,
            AlertDescription alertDescription,
            string error) : base(level, alertDescription, null, null, error, null)
        {
        }
    }
}
