using System;

namespace Arctium.Cryptography.FileFormats.Exceptions
{
    public class InvalidFileFormatException : Exception
    {
        public InvalidFileFormatException(string message) : base(message)
        {
        }
    }
}
