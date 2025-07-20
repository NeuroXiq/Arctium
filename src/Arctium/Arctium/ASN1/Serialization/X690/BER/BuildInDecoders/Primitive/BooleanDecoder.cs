using Arctium.Standards.ASN1.ObjectSyntax.Types;
using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Serialization.Exceptions;
using Arctium.Standards.ASN1.Serialization.X690.DER;
using Boolean = Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes.Boolean;

namespace Arctium.Standards.ASN1.Serialization.X690.BER.BuildInDecoders.Primitive
{
    public class BooleanDecoder :IX690Decoder<Boolean>
    {
        public Boolean Decode(byte[] buffer, long offset, long length)
        {
            if (length != 1)
            {
                throw new X690DecoderException(
                    "Invalid BER-encoding of the boolean value.\n" +
                    $"Value shall be encoded as an 1-byte value but current content length is {length}");
            }

            bool booleanValue = buffer[offset] > 0;

            return new Boolean(booleanValue);
        }
    }
}
