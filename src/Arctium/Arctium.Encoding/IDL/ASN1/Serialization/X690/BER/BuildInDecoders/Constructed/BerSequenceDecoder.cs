using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;
using System.Collections.Generic;

namespace Arctium.Encoding.IDL.ASN1.Serialization.X690.BER.BuildInDecoders.Constructed
{
    public class BerSequenceDecoder : IConstructorDecoder
    {
        readonly Tag tag = BuildInTag.Sequence;
        public Tag DecodesTag { get { return tag; } }

        public CodingFrame Frame { get; set; }

        List<Asn1TaggedType> sequenceValues;

        public BerSequenceDecoder()
        {
            sequenceValues = new List<Asn1TaggedType>();
        }

        public BerSequenceDecoder(CodingFrame frame)
        {
            Frame = frame;
            sequenceValues = new List<Asn1TaggedType>();
        }

        public bool CanPush(CodingFrame frame)
        {
            return true;
        }

        public Asn1TaggedType GetPopValue()
        {
            return new Sequence(sequenceValues);
        }

        public void Add(CodingFrame frame, Asn1TaggedType decodedType)
        {
            sequenceValues.Add(decodedType);
        }

        public IConstructorDecoder Create(CodingFrame frame)
        {
            return new BerSequenceDecoder(frame);
        }
    }
}
