using System;

namespace Arctium.Shared.Exceptions
{
    public class ArctiumException : Exception
    {
        public ArctiumException(string message) : base(message)
        {
        }
    }
}
