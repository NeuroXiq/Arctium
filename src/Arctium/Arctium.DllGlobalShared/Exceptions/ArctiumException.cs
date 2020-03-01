using System;

namespace Arctium.DllGlobalShared.Exceptions
{
    public class ArctiumException : Exception
    {
        public ArctiumException(string message) : base(message)
        {
        }
    }
}
