using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Encoding.IDL.ASN1.Serialization.Exceptions;
using Arctium.Encoding.IDL.ASN1.Serialization.X690;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;

namespace Arctium.Cryptography.Documents.Certificates.X509Certificates.X509v3Certificate.Asn1
{
    class Asn1UniqueIdentifierDecoder : IConstructorDecoder
    {
        const long UniqueIdentifierTypeTagNumber = 3;
        private readonly Tag decodesTag = new Tag(TagClass.Private, UniqueIdentifierTypeTagNumber);
        public Tag DecodesTag => decodesTag;
        public CodingFrame InitializationFrame { get; private set; }

        Asn1TaggedType currentDecodedType;

        public Asn1UniqueIdentifierDecoder() { }
        public Asn1UniqueIdentifierDecoder(CodingFrame initializationFrame)
        {
            InitializationFrame = initializationFrame;
        }

        public void Add(CodingFrame frame, Asn1TaggedType decodedType)
        {
            if (currentDecodedType != null)
            {
                throw new X690DecoderException(
                    "Cannot assign second item to a UniqueIdentifierConstructor.\n" +
                    "Value of the unique identifier must consist of single UniqueIdentifierType with Sequence as an internal value but trying\n" +
                    "to assign next value when value is already assigned.", frame, this);
            }

            this.currentDecodedType = (Sequence)decodedType;
        }

        public bool CanPush(CodingFrame frame)
        {
            return currentDecodedType == null;
        }

        public IConstructorDecoder Create(CodingFrame frame)
        {
            return new Asn1UniqueIdentifierDecoder(frame);
        }

        public Asn1TaggedType GetPopValue()
        {
            return currentDecodedType;
        }
    }
}
