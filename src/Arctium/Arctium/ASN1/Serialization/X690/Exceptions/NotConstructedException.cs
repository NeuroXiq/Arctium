using System;

namespace Arctium.Standards.ASN1.Serialization.X690.Exceptions
{
    /// <summary>
    /// Exception is thrown where ASN1 is not a constructed one
    /// </summary>
    public class NotConstructedException : Exception
    {
        public NotConstructedException(string message) : base(message)
        {

        }
    }
}
