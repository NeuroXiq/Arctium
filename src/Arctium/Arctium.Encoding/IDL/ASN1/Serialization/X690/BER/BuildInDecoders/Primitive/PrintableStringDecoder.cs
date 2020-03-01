using System;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;

namespace Arctium.Encoding.IDL.ASN1.Serialization.X690.BER.BuildInDecoders.Primitive
{
    class PrintableStringDecoder : IPrimitiveDecoder
    {
        public Tag DecodesTag { get { return BuildInTag.PrintableString; } }

        public Asn1TaggedType Decode(CodingFrame frame, byte[] buffer, long offset, out long contentLength)
        {
            contentLength = frame.ContentLength.Length;
            string result = System.Text.Encoding.ASCII.GetString(buffer, (int)offset, (int)contentLength);

            return new PrintableString(result);
        }
    }
}
