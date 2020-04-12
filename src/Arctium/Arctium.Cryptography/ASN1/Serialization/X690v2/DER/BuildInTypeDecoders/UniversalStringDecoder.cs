using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using System.Text;

namespace Arctium.Cryptography.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders
{
    class UniversalStringDecoder : IDerTypeDecoder<UniversalString>
    {
        public UniversalString Decode(byte[] buffer, long offset, long length)
        {
            string decodedString = Encoding.UTF8.GetString(buffer, (int)(offset), (int)length);

            
            return new UniversalString(decodedString);
        }
    }
}
