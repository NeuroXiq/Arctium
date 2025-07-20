using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using System.Text;

namespace Arctium.Standards.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders
{
    internal class TeletextStringDecoder : IDerTypeDecoder<TeletextString>
    {
        public TeletextString Decode(byte[] buffer, long offset, long contentLength)
        {
            string s = Encoding.ASCII.GetString(buffer, (int)offset, (int)contentLength);

            return new TeletextString(s);
        }
    }
}
