using Arctium.Cryptography.Exceptions;

namespace Arctium.Cryptography.HashFunctions.Hashes.Exceptions
{
    class HashFunctionsExceptionInternal : ArctiumCryptographyExceptionInternal
    {
        public HashFunctionsExceptionInternal(string message, string description, object throwingClassInstance) : base(message, description, throwingClassInstance)
        {
        }
    }
}
