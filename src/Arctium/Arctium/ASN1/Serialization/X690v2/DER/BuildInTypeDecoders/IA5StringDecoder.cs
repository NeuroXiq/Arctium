using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using System.Text;

namespace Arctium.Standards.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders
{
    public class IA5StringDecoder : IDerTypeDecoder<IA5String>
    {
        public IA5String Decode(byte[] buffer, long offset, long contentLength)
        {
            return Encoding.UTF8.GetString(buffer, (int)offset, (int)contentLength);
        }
    }
}
