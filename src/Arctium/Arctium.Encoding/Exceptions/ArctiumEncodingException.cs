using Arctium.DllGlobalShared.Exceptions;

namespace Arctium.Encoding.Exceptions
{
    // this is a mistake  (including interval equivalent), todo remove
    //TODO ASN1 remove class
    public class ArctiumEncodingException : ArctiumException
    {
        public ArctiumEncodingException(string message) : base(message)
        {

        }
    }
}
