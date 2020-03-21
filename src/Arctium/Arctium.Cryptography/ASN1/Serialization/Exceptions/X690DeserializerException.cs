using Arctium.Cryptography.ASN1.Exceptions;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;

namespace Arctium.Cryptography.ASN1.Serialization.Exceptions
{
    public class X690DeserializerException : Asn1Exception
    {
        internal BufferFrame CachedBufferFrame;

        internal X690DeserializerException(BufferFrame bufferFrame, string message) : base(message)
        {
            CachedBufferFrame = bufferFrame;
        }
    }
}
