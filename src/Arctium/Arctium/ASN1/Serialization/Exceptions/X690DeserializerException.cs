using Arctium.Standards.ASN1.Exceptions;
using Arctium.Standards.ASN1.Serialization.X690.DER;

namespace Arctium.Standards.ASN1.Serialization.Exceptions
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
