using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.Model;
using System;

namespace Arctium.Standards.Connection.Tls.Tls13.Protocol
{
    internal class Tls13ReceivedAlertException  : Tls13AlertException
    {
        public Tls13ReceivedAlertException(AlertLevel level,
            AlertDescription alertDescription,
            string error) : base(level, alertDescription, null, null, error, null)
        {
        }
    }
}
