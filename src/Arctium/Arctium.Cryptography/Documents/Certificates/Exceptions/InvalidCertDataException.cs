using Arctium.DllGlobalShared.Exceptions;

namespace Arctium.Cryptography.Documents.Certificates.Exceptions
{
    public class InvalidCertDataException : ArctiumException
    {
        public InvalidCertDataException(string message) : base(message)
        {

        }
    }
}
