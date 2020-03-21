using Arctium.Cryptography.ASN1.Exceptions;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using System;

namespace Arctium.Cryptography.ASN1.Serialization.Exceptions
{
    public class X690DecoderException : Asn1Exception
    {
        public X690DecoderException(string message) : base(message)
        {
        }

    }
}
