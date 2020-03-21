using System;

namespace Arctium.Cryptography.FileFormat.Exceptions
{
    public class InvalidFileFormatException : Exception
    {
        public InvalidFileFormatException(string message) : base(message)
        {
        }
    }
}
