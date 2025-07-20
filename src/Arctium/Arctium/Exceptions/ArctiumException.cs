using System;

namespace Arctium.Shared.Exceptions
{
    public class ArctiumException : Exception
    {
        public ArctiumException() : base() { }

        public ArctiumException(string message) : base(message)
        {
        }
    }
}
