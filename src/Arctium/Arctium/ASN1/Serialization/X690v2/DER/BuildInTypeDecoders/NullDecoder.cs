using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Serialization.Exceptions;

namespace Arctium.Standards.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders
{
    public class NullDecoder : IDerTypeDecoder<Null>
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
