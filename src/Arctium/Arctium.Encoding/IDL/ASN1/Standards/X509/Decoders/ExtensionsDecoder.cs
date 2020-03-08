using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Encoding.IDL.ASN1.Serialization.Exceptions;
using Arctium.Encoding.IDL.ASN1.Serialization.X690;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;
using Arctium.Encoding.IDL.ASN1.Standards.X509.Types;

namespace Arctium.Encoding.IDL.ASN1.Standards.X509.Decoders
{
    class ExtensionsDecoder : IConstructorDecoder
    {
        public Tag DecodesTag => X509Type.ExtensionsTag;
        public CodingFrame InitializationFrame { get; private set; }

        Extensions currentDecodedType;

        public ExtensionsDecoder() { }
        public ExtensionsDecoder(CodingFrame initializationFrame)
        {
            InitializationFrame = initializationFrame;
        }

        public void Add(CodingFrame frame, Asn1TaggedType decodedType)
        {
            if (currentDecodedType != null)
            {
                throw new X690DecoderException(
                    "Cannot assign second item to a ExtensionsDecoder.\n" +
                    "Value of the unique identifier must consist of single with Sequence object as an internal value but trying\n" +
                    "to assign next value when value is already assigned.", frame, this);
            }

            this.currentDecodedType = new Extensions((Sequence)decodedType);
        }

        public bool CanPush(CodingFrame frame)
        {
            return currentDecodedType == null;
        }

        public IConstructorDecoder Create(CodingFrame frame)
        {
            return new ExtensionsDecoder(frame);
        }

        public Asn1TaggedType GetPopValue()
        {
            return currentDecodedType;
        }
    }
}
