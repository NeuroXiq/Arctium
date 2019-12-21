using System;

namespace Arctium.Connection.Tls.Exceptions
{
    ///<summary>Exception is thrown when received aler messages of warning level</summary>
    public class ReceivedWarningAlertException : Exception
    {
        public int AlertDescriptionNumber { get; private set; }
        public string When { get; private set; }
        public string Where { get; private set; }
        public string Description { get; private set; }

        public ReceivedWarningAlertException(int alertDescription, string when, string where, string description) : base(description)
        {
            AlertDescriptionNumber = alertDescription;
            When = when;
            Where = where;
            Description = description;
        }
    }
}
