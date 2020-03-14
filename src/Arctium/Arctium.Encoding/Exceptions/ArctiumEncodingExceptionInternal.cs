using Arctium.DllGlobalShared.Exceptions;

namespace Arctium.Encoding.Exceptions
{
    //TODO ASN1 remove class
    public class ArctiumEncodingExceptionInternal : ArctiumExceptionInternal
    {
        public ArctiumEncodingExceptionInternal(string message, string description, object throwingClassInstance) : base(message, description, throwingClassInstance)
        {
        }
    }
}
