using Arctium.Shared.Helpers.Buffers;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using System;

namespace Arctium.Cryptography.ASN1.Serialization.X690.BER.BuildInDecoders.Primitive
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
