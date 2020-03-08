using System;
using System.Collections.Generic;
using Arctium.Encoding.IDL.ASN1.Exceptions;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;

namespace Arctium.Encoding.IDL.ASN1.Serialization.X690.DER
{
    /// <summary>
    /// Special purpose root-constructors.
    /// This consntructor is 'before' all data in some encoded fields in asn1 document
    /// and behave as a 'container' for all types in the encoded structure.
    /// Typically 'container' value will have single value of sequence/sequence-of, set type.
    /// Just to facilitate work with deserializer.
    /// </summary>

    class SpecialRootConstructor : IConstructorDecoder
    {
        public Tag DecodesTag => throw new NotImplementedException();

        public CodingFrame InitializationFrame { get; set; }

        Tag IConstructorDecoder.DecodesTag => throw new NotImplementedException();

        public List<Asn1TaggedType> container = new List<Asn1TaggedType>();

        public SpecialRootConstructor(long length)
        {
            InitializationFrame = new CodingFrame() { ContentLength = new ContentLength(length) };
        }

        public void Add(CodingFrame frame, Asn1TaggedType decodedType)
        {
            container.Add(decodedType);
        }

        public bool CanPush(CodingFrame frame) => true;
        public IConstructorDecoder Create(CodingFrame frame) => null;
        public Asn1TaggedType GetPopValue() => throw new Asn1InternalException("Cannot pop value from the special-root contructor decoder", "", this);
    }
}
