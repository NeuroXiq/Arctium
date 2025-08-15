using Arctium.Shared;
using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using System;

namespace Arctium.Standards.ASN1.Serialization.X690.BER.BuildInDecoders.Primitive
{
    public class IntegerDecoder: IX690Decoder<Integer>
    {
        public Integer Decode(byte[] buffer, long offset, long length)
        {            
            byte[] value = new byte[length];
            MemCpy.Copy(buffer, offset, value, 0, length);

            return new Integer(value);
        }
    }
}
