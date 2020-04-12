using Arctium.Shared.Helpers.DataStructures;
using System;

namespace Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes
{
    /// <summary>
    /// Maps Type of Asn1 object to Universal tag of this type 
    /// and reverse, tag to type.
    /// </summary>
    public static class TagTypeMap
    {
        static DoubleDictionary<Type, Tag> map = new DoubleDictionary<Type, Tag>();

        public static Tag Get(Type type) => map[type];
        public static Type Get(Tag tag) => map[tag];

        static TagTypeMap()
        {
            Initialize();
        }

        private static void Initialize()
        {
            map[BuildInTag.Integer] = typeof(Integer);
            map[BuildInTag.Bitstring] = typeof(BitString);
            map[BuildInTag.ObjectIdentifier] = typeof(ObjectIdentifier);
            map[BuildInTag.UTCTime] = typeof(UTCTime);
            map[BuildInTag.GeneralizedTime] = typeof(GeneralizedTime);
            map[BuildInTag.PrintableString] = typeof(PrintableString);
            map[BuildInTag.UTF8String] = typeof(UTF8String);
            map[BuildInTag.Boolean] = typeof(Boolean);
            map[BuildInTag.OctetString] = typeof(OctetString);
            map[BuildInTag.IA5String] = typeof(IA5String);
        }
    }
}
