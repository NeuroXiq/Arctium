using Arctium.Cryptography.ASN1.ObjectSyntax.Types;
using System;

namespace Arctium.Cryptography.ASN1.Serialization.X690.Exceptions
{
    public class UnexpectedTagException : Exception
    {
        public Tag ExpectedTag { get; private set; }
        public Tag CurrentTag { get; private set; }

        public UnexpectedTagException(Tag expected, Tag current, string message) : base(message)
        {
            ExpectedTag = expected;
            CurrentTag = current;
        }

        public static UnexpectedTagException Build(Tag expected, Tag current, string info)
        {
            string message = "Unexpected tag was found on X690 Serialization process" +
                $"Expected tag: {expected.ToString()} but current funded tag: {current}." +
                info == null ? "" : info;

            return new UnexpectedTagException(expected, current, info);
        }
    }
}
