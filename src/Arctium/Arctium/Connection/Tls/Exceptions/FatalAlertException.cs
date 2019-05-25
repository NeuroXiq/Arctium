using System;

namespace Arctium.Connection.Tls.Exceptions
{
    ///<summary>Exception is throw when fatal exception occur during TLS transmission (at any point)</summary>
    public class FatalAlertException : Exception
    {
        ///<summary>On which internal layer exception occur</summary>
        public string Where { get; private set; }
        ///<summary>At which point of processing exception occur</summary>
        public string When { get; private set; }
        ///<summary>Unique number of alert description associated with this exception</summary>
        public int AlertDescriptionNumber { get; private set; }
        ///<summary>More informations about exception</summary>
        public string Description { get; private set; }

        ///<summary>Exception is thrown when fatal alert error occur during processing TLS</summary>
        public FatalAlertException(
            string where, string when, int alertNumber, string description) : base(description)
        {
            Where = where;
            When = when;
            AlertDescriptionNumber = alertNumber;
            Description = description;
        }
    }
}
