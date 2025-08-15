using Arctium.Shared;
using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Standards.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders
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
