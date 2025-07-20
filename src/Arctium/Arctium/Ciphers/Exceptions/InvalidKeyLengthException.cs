using System;

namespace Arctium.Cryptography.Ciphers.Exceptions
{
    public class InvalidKeyLengthException : Exception
    {
        public InvalidKeyLengthException(string message) : base(message)
        {

        }
    }
}
