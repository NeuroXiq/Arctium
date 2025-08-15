using Arctium.Shared;
using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Standards.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders
{
    public class OctetStringDecoder : IDerTypeDecoder<OctetString>
    {
        public OctetString Decode(byte[] buffer, long offset, long length)
        {
            byte[] stringValue = new byte[length];

            MemCpy.Copy(buffer, offset, stringValue, 0, length);

            
            return new OctetString(stringValue);
        }
    }
}
