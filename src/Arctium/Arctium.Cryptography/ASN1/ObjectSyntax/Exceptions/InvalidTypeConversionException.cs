using Arctium.Cryptography.ASN1.Exceptions;
using System;

namespace Arctium.Cryptography.ASN1.ObjectSyntax.Exceptions
{
    class InvalidTypeConversionException : Asn1Exception
    {
        public string ExpectedTypeName { get; set; }
        public string CurrentTypeName { get; set; }

        public Type ExpectedType { get; set; }
        public Type CurrentType { get; set; }

        public InvalidTypeConversionException(string message,  
            string expectedTypeName, 
            string currentTypeName,
            Type expected,
            Type current) : base(message) {

            ExpectedTypeName = expectedTypeName;
            CurrentTypeName = currentTypeName;
            ExpectedType = expected;
            CurrentType = CurrentType;
        }


        public void Create<TExpected>(object current)
        {
            new InvalidTypeConversionException(
                "Cannot convert specific.",
                typeof(TExpected).Name,
                current == null ? "<null>" : current.GetType().Name,
                typeof(TExpected),
                current == null ? null : current.GetType());
        }
    }
}
