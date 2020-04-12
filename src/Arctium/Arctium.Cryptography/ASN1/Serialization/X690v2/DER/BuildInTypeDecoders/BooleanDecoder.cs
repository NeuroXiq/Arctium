using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.Exceptions;

namespace Arctium.Cryptography.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders
{
    public class BooleanDecoder :IDerTypeDecoder<Boolean>
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
