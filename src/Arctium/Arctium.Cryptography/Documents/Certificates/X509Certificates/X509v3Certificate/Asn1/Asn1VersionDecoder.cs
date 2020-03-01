using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Encoding.IDL.ASN1.Serialization.Exceptions;
using Arctium.Encoding.IDL.ASN1.Serialization.X690;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;

namespace Arctium.Cryptography.Documents.Certificates.X509Certificates.X509v3Certificate.Asn1
{
    class Asn1VersionDecoder : IConstructorDecoder
    {
        // x509 cert private tag, ' [0] => Version '
        private readonly Tag tag = new Tag(TagClass.Private, 0);
        private CodingFrame cachedFrame;
        private readonly Tag expectedAddValue = BuildInTag.Integer;

        Asn1VersionType decodedVersion;

        public Asn1VersionDecoder()
        {

        }

        public Asn1VersionDecoder(CodingFrame frame)
        {
            this.cachedFrame = frame;
        }

        public Tag DecodesTag { get { return tag; } }

        public CodingFrame Frame { get { return this.cachedFrame; } }

        public void Add(CodingFrame frame, Asn1TaggedType decodedType)
        {

            if (!expectedAddValue.Equals(frame.Tag))
                throw new X690DecoderException(
                    "Cannot add this tag value to the Asn1VersionDecoder (Constructor) because this is not an expected integer type",
                    this);

            if(decodedVersion != null)
                throw new X690DecoderException("Cannot assign vesion second type. Expected only one version in data.", this);

            decodedVersion = new Asn1VersionType(decodedType);
        }

        public bool CanPush(CodingFrame frame)
        {
            // integer / universal
            return frame.TagNumber == 2 &&
                   frame.ClassNumber == 0;
        }

        public IConstructorDecoder Create(CodingFrame frame)
        {
            return new Asn1VersionDecoder(frame);
        }

        public Asn1TaggedType GetPopValue()
        {
            return decodedVersion;
        }
    }
}
