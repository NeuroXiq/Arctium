using System;

namespace Arctium.Standards.ASN1.Standards.X509.Exceptions
{
    public class X509DecodingException : Exception
    {
        public X509DecodingException(string message) : base(message)
        {
        }
    }
}
