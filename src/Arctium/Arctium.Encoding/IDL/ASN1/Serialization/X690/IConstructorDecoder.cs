using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;

namespace Arctium.Encoding.IDL.ASN1.Serialization.X690
{
    public interface IConstructorDecoder
    {
        Tag  DecodesTag { get; }
        CodingFrame Frame { get; }
        bool CanPush(CodingFrame frame);
        void Add(CodingFrame frame, Asn1TaggedType decodedType);
        Asn1TaggedType GetPopValue();
        IConstructorDecoder Create(CodingFrame frame);
    }
}
