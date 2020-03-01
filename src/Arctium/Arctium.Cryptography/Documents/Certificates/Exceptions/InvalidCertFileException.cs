using Arctium.DllGlobalShared.Exceptions;

namespace Arctium.Cryptography.Documents.Certificates.Exceptions
{
    class InvalidCertFileException : ArctiumException
    {
        public InvalidCertFileException(string message) : base(message)
        {

        }
    }
}
