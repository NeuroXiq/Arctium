using Arctium.Connection.Tls.Tls13.Model;
using System;

namespace Arctium.Connection.Tls.Tls13.API
{
    public class Tls13Exception : Exception
    {
        public AlertDescription? AlertDescription { get; private set; }

        public Tls13Exception(string message, AlertDescription? alertDescription) : base(message)
        {
            this.AlertDescription = alertDescription;
        }

        public Tls13Exception(string message) : base(message)
        {
        }
    }
}
