using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Encoding.IDL.ASN1.Serialization.Exceptions;
using Arctium.Encoding.IDL.ASN1.Serialization.X690;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;
using Arctium.Encoding.IDL.ASN1.Standards.X509.Types;

namespace Arctium.Encoding.IDL.ASN1.Standards.X509.Decoders
{
    class VersionDecoder : IConstructorDecoder
    {
        // x509 cert private tag, ' [0] => Version '
        //private readonly Tag tag = new Tag(TagClass.Private, 0);
        private CodingFrame cachedFrame;
        private readonly Tag expectedAddValue = BuildInTag.Integer;

        Version decodedVersion;

        public VersionDecoder()
        {

        }

        public VersionDecoder(CodingFrame frame)
        {
            this.cachedFrame = frame;
        }

        public Tag DecodesTag { get { return X509Type.VersionTag; } }

        public CodingFrame InitializationFrame { get { return this.cachedFrame; } }

        public void Add(CodingFrame frame, Asn1TaggedType decodedType)
        {

            if (!expectedAddValue.Equals(frame.Tag))
                throw new X690DecoderException(
                    "Cannot add this tag value to the Asn1VersionDecoder (Constructor) because this is not an expected integer type",
                    this);

            if(decodedVersion != null)
                throw new X690DecoderException("Cannot assign vesion second type. Expected only one version in data.", this);

            decodedVersion = new Version(decodedType);
        }

        public bool CanPush(CodingFrame frame)
        {
            return decodedVersion == null;
        }

        public IConstructorDecoder Create(CodingFrame frame)
        {
            return new VersionDecoder(frame);
        }

        public Asn1TaggedType GetPopValue()
        {
            return decodedVersion;
        }
    }
}
