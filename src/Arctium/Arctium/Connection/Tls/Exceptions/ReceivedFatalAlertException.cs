using System;

namespace Arctium.Standards.Connection.Tls.Exceptions
{
    ///<summary>Exception is throw when received aler message of fatal level</summary>
    public class ReceivedFatalAlertException : Exception
    {
        public int AlertDescriptionNumber { get; private set; }
        public string Where { get; private set; }
        public string When { get; private set; }
        public string Descrpition { get; private set; }

        public ReceivedFatalAlertException(int alerDescriptionNumber, string where, string when, string description) : base(description)
        {
            AlertDescriptionNumber = alerDescriptionNumber;
            Where = where;
            When = when;
            Descrpition = description;
        }
    }
}
