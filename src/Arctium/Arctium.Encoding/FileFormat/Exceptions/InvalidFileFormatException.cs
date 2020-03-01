using Arctium.Encoding.Exceptions;

namespace Arctium.Encoding.FileFormat.Exceptions
{
    public class InvalidFileFormatException : ArctiumEncodingException
    {
        public InvalidFileFormatException(string message) : base(message)
        {
        }
    }
}
