using System;

namespace Arctium.Shared
{
    public class StandardException : Exception
    {
        public string StandardName { get; private set; }

        public StandardException(string standardName, string message, string standardExceptionText, Exception innerException) : base (message, innerException)
        {
            this.StandardName = standardName;
        }

        public StandardException(string standardName, string standardExceptionText) : base (standardExceptionText)
        {
            this.StandardName = standardName;
        }
    }
}
