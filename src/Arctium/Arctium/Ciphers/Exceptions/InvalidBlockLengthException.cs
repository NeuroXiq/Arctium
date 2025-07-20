using System;

namespace Arctium.Cryptography.Ciphers.Exceptions
{
    public class InvalidBlockLengthException : Exception
    {
        public InvalidBlockLengthException(string message) : base(message) { }
    }
}
