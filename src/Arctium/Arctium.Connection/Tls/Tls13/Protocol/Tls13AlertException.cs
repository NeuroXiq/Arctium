using Arctium.Connection.Tls.Tls13.API;
using Arctium.Connection.Tls.Tls13.Model;

namespace Arctium.Connection.Tls.Tls13.Protocol
{
    internal class Tls13AlertException  : Tls13Exception
    {
        public AlertDescription AlertDescription { get; private set; }
        public AlertLevel AlertLevel { get; private set; }

        public Tls13AlertException(AlertLevel level,
            AlertDescription alertDescription,
            string tlsMessageName,
            string field,
            string error) : base(tlsMessageName, field, error)
        {
            AlertDescription = alertDescription;
            AlertLevel = level;
        }
    }
}
