using Arctium.Connection.Tls.Protocol.AlertProtocol;
using System;

namespace Arctium.Connection.Tls.Operator
{
    class OperatorFatalAlertException : Exception
    {
        public AlertDescription Description { get; private set; }

        public OperatorFatalAlertException(AlertDescription description,  string message) : base(message)
        {
            Description = description;
        }
    }
}
