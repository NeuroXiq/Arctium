using System;
using System.Runtime.Serialization;

namespace Arctium.Connection.Tls.ProtocolStream.HighLevelLayer.Crypto
{
    [Serializable]
    internal class NotImplementerException : Exception
    {
        public NotImplementerException()
        {
        }

        public NotImplementerException(string message) : base(message)
        {
        }

        public NotImplementerException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected NotImplementerException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}