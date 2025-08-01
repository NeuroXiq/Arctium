using Arctium.Protocol.Tls13;
using Arctium.Protocol.Tls13Impl.Model;
using System;

namespace Arctium.Protocol.Tls13Impl.Protocol
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
