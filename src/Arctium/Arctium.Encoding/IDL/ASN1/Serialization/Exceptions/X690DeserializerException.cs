using Arctium.Encoding.IDL.ASN1.Exceptions;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;

namespace Arctium.Encoding.IDL.ASN1.Serialization.Exceptions
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
