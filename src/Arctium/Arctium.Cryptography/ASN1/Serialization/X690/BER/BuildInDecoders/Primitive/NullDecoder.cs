using Arctium.Cryptography.ASN1.ObjectSyntax.Types;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.Exceptions;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;

namespace Arctium.Cryptography.ASN1.Serialization.X690.BER.BuildInDecoders.Primitive
{
    public class NullDecoder : IX690Decoder<Null>
    {
        public NullDecoder()
        {
        }

        public Null Decode(byte[] buffer, long offset, long length)
        {
            if (length != 0) throw new X690DecoderException("Invalid length of the Null coding value. Length must be 0");
            
            return new Null();
        }
    }
}
