using Arctium.Shared.Helpers.Buffers;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Cryptography.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders
{
    public class IntegerDecoder: IDerTypeDecoder<Integer>
    {
        public Integer Decode(byte[] buffer, long offset, long length)
        {            
            byte[] value = new byte[length];
            MemCpy.Copy(buffer, offset, value, 0, length);

            return new Integer(value);
        }
    }
}
