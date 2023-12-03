using Arctium.Standards.Connection.Tls13;
using Arctium.Standards.Connection.Tls13Impl.Model;
using System;

namespace Arctium.Standards.Connection.Tls13Impl.Protocol
{
    internal class Tls13AlertException : Tls13Exception
    {
        internal AlertDescription AlertDescription { get; private set; }
        internal AlertLevel AlertLevel { get; private set; }

        internal Tls13AlertException(AlertLevel level,
            AlertDescription alertDescription,
            string tlsMessageName,
            string field,
            string error,
            Exception innerException) : base(tlsMessageName, field, FormatAlertError(level, alertDescription, error), innerException)
        {
            AlertDescription = alertDescription;
            AlertLevel = level;
        }

        internal Tls13AlertException(AlertLevel level,
            AlertDescription alertDescription,
            string tlsMessageName,
            string field,
            string error) : this(level, alertDescription, tlsMessageName, field, error, null)
        {
        }

        static string FormatAlertError(AlertLevel level, AlertDescription description, string error)
        {
            return string.Format("AlertLevel: {0}; AlertDescription {1} ({2}), error: {3}", level, description.ToString(), (int)description, error);
        }
    }
}
