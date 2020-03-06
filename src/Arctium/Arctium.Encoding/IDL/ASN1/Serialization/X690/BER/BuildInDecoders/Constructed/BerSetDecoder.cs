using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;
using System.Collections.Generic;

namespace Arctium.Encoding.IDL.ASN1.Serialization.X690.BER.BuildInDecoders.Constructed
{
    public class BerSetDecoder : IConstructorDecoder
    {
        public Tag DecodesTag { get { return BuildInTag.Set; } }

        public CodingFrame InitializationFrame { get; set; }

        List<Asn1TaggedType> setContainer = new List<Asn1TaggedType>();


        public BerSetDecoder() { }
        public BerSetDecoder(CodingFrame frame)
        {
            InitializationFrame = frame;
        }

        public void Add(CodingFrame frame, Asn1TaggedType decodedType)
        {
            setContainer.Add(decodedType);
        }

        public bool CanPush(CodingFrame frame)
        {
            return true;
        }

        public IConstructorDecoder Create(CodingFrame frame)
        {
            return new BerSetDecoder(frame);
        }

        public Asn1TaggedType GetPopValue()
        {
            return new Set(setContainer);
        }
    }
}
