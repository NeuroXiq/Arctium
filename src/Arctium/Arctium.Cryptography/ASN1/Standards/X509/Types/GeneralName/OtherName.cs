using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Cryptography.ASN1.Standards.X509.Types
{
    public struct OtherName
    {
        public ObjectIdentifier TypeId { get; private set; }

        /// <summary>
        /// Encoded content, all raw data bytes after EXPLICIT [0] tag in other name DER structure.
        /// For future update/processing
        /// </summary>
        public byte[] EncodedContent { get; private set; }

        public OtherName(ObjectIdentifier oid, byte[] innerContent) : this()
        {
            this.TypeId = oid;
            this.EncodedContent = innerContent;
        }
    }
}
