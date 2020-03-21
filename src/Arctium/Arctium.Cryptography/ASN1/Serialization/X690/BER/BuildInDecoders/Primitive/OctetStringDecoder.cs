using Arctium.Shared.Helpers.Buffers;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Cryptography.ASN1.Serialization.X690.BER.BuildInDecoders.Primitive
{
    public class OctetStringDecoder : IX690Decoder<OctetString>
    {
        public OctetString Decode(byte[] buffer, long offset, long length)
        {
            byte[] stringValue = new byte[length];

            ByteBuffer.Copy(buffer, offset, stringValue, 0, length);

            
            return new OctetString(stringValue);
        }
    }
}
