using Arctium.DllGlobalShared.Constants;

namespace Arctium.Encoding.IDL.ASN1.Serialization.X690.DER
{
    public class DerDeserializerConfig
    {
        public static DerDeserializerConfig Default { get; }


        public long MaxValueLength = 64 * Size.MB;


    }
}
