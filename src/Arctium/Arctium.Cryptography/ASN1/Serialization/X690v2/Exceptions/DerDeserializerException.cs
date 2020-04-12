using System;

namespace Arctium.Cryptography.ASN1.Serialization.X690v2.Exceptions
{
    public class DerDeserializerException : Exception
    {
        public byte[] Buffer { get; private set; }
        public long Offset { get; private set; }

        public DerDeserializerException(string message, byte[] buffer, long offset) : base(message)
        {
            Buffer = buffer;
            Offset = offset;
        }

        
    }
}
