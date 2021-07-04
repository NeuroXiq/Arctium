using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Standards.ASN1.Standards.X509.X509Cert
{
    public class OtherName
    {
        public ObjectIdentifier TypeId { get; private set; }

        /// <summary>
        /// Encoded content, all raw data bytes after EXPLICIT [0] tag in other name DER structure.
        /// Prepared for future update/processing
        /// </summary>
        public byte[] EncodedContent { get; private set; }

        public OtherName(ObjectIdentifier oid, byte[] innerContent)
        {
            this.TypeId = oid;
            this.EncodedContent = innerContent;
        }
    }
}
