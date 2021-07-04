using Arctium.Standards.ASN1.ObjectSyntax.Types;
using Arctium.Standards.ASN1.Serialization.X690.DER;

namespace Arctium.Standards.ASN1.Serialization.X690
{
    public interface IX690Decoder<T>
    {
        T Decode(byte[] buffer, long offset, long contentLength);
    }
}
