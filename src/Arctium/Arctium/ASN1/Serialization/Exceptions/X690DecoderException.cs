using Arctium.Standards.ASN1.Exceptions;
using Arctium.Standards.ASN1.Serialization.X690.DER;
using System;

namespace Arctium.Standards.ASN1.Serialization.Exceptions
{
    public class X690DecoderException : Asn1Exception
    {
        public X690DecoderException(string message) : base(message)
        {
        }

    }
}
