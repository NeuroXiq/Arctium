using Arctium.Standards.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders;

namespace Arctium.Standards.ASN1.Serialization.X690v2.DER
{
    public class DerDeserializedContext
    {
        public DerDecoded Root { get; private set; }
        public DerDecoded Current { get; set; }
        public DerTypeDecoder DerTypeDecoder { get; private set; }
        public byte[] Buffer { get; private set; }

        public DerDeserializedContext(DerDecoded root, byte[] buffer)
        {
            this.Root = root;
            this.Buffer = buffer;
            this.DerTypeDecoder = new DerTypeDecoder(buffer);
            this.Current = root;
        }
    }
}
