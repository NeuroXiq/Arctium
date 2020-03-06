using Arctium.Encoding.IDL.ASN1.Exceptions;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;
using System;

namespace Arctium.Encoding.IDL.ASN1.Serialization.Exceptions
{
    public class X690DecoderException : Asn1Exception
    {
        public object Decoder { get; set; }

        public CodingFrame Frame { get; set; }
        public X690DecoderException(string message, object decoder) : this(message, new CodingFrame(), decoder)
        {
        }

        public X690DecoderException(string message, CodingFrame frame ,object decoder) : base(message)
        {
            Decoder = decoder;
            Frame = frame;
        }
    }
}
