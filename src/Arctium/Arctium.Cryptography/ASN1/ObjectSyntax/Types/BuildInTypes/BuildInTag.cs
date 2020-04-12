using System;
using System.Collections.Generic;

namespace Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes
{
    /// <summary>
    /// Creates new instance of <see cref="Tag"/> for build in ASN.1 types
    /// </summary>
    public static class BuildInTag
    {
        public static readonly Tag  RESERVED_0 = new Tag(TagClass.Universal, 0);
        public static readonly Tag  Boolean = new Tag(TagClass.Universal, 1);
        public static readonly Tag  Integer = new Tag(TagClass.Universal, 2);
        public static readonly Tag  Bitstring = new Tag(TagClass.Universal, 3);
        public static readonly Tag  OctetString = new Tag(TagClass.Universal, 4);
        public static readonly Tag  Null = new Tag(TagClass.Universal, 5);
        public static readonly Tag  ObjectIdentifier = new Tag(TagClass.Universal, 6);
        public static readonly Tag  ObjectDescriptor = new Tag(TagClass.Universal, 7);
        public static readonly Tag  External = new Tag(TagClass.Universal, 8);
        public static readonly Tag  InstanceOf = new Tag(TagClass.Universal, 8);
        public static readonly Tag  Real = new Tag(TagClass.Universal, 9);
        public static readonly Tag  Enumerated = new Tag(TagClass.Universal, 10);
        public static readonly Tag  EmbeddedPdv = new Tag(TagClass.Universal, 11);
        public static readonly Tag  UTF8String = new Tag(TagClass.Universal, 12);
        public static readonly Tag  RelativeObjectIdentifier = new Tag(TagClass.Universal, 13);
        public static readonly Tag  Time = new Tag(TagClass.Universal, 14);
        public static readonly Tag  ReservedForFutureEditions = new Tag(TagClass.Universal, 15);
        public static readonly Tag  Sequence = new Tag(TagClass.Universal, 16);
        public static readonly Tag  SequenceOf = new Tag(TagClass.Universal, 16);
        public static readonly Tag  Set = new Tag(TagClass.Universal, 17);
        public static readonly Tag  SetOf = new Tag(TagClass.Universal, 17);
        public static readonly Tag  NumericString = new Tag(TagClass.Universal, 18);
        public static readonly Tag  PrintableString = new Tag(TagClass.Universal, 19);
        public static readonly Tag  TeletexString = new Tag(TagClass.Universal, 20);
        public static readonly Tag  VideotexString = new Tag(TagClass.Universal, 21);
        public static readonly Tag  IA5String = new Tag(TagClass.Universal, 22);
        public static readonly Tag  GraphicString = new Tag(TagClass.Universal, 25);
        public static readonly Tag  VisibleString = new Tag(TagClass.Universal, 26);
        public static readonly Tag  GeneralString = new Tag(TagClass.Universal, 27);
        public static readonly Tag  UniversalString = new Tag(TagClass.Universal, 28);
        public static readonly Tag  CharacterString_29 = new Tag(TagClass.Universal, 29);
        public static readonly Tag  BMPString = new Tag(TagClass.Universal, 30);
        public static readonly Tag  UTCTime = new Tag(TagClass.Universal, 23);
        public static readonly Tag  GeneralizedTime = new Tag(TagClass.Universal, 24);
        public static readonly Tag  Date = new Tag(TagClass.Universal, 31);
        public static readonly Tag  TimeOfDay = new Tag(TagClass.Universal, 32);
        public static readonly Tag  DateTime = new Tag(TagClass.Universal, 33);
        public static readonly Tag  Duration = new Tag(TagClass.Universal, 34);
        public static readonly Tag  OIDInternationalizedResourceIdentifier = new Tag(TagClass.Universal, 35);
        public static readonly Tag  RelativeOIDInternationalizedResourceIdentifier = new Tag(TagClass.Universal, 36);
        public static readonly Tag  RESERVED_37_AND_MORE = new Tag(TagClass.Universal, 37);
    }
}

/* public static readonly Func<Tag> RESERVED_0 = ()=> new Tag(TagClass.Universal, 0);
        public static readonly Func<Tag> Boolean = ()=> new Tag(TagClass.Universal, 1);
        public static readonly Func<Tag> Integer = ()=> new Tag(TagClass.Universal, 2);
        public static readonly Func<Tag> Bitstring = ()=> new Tag(TagClass.Universal, 3);
        public static readonly Func<Tag> Octetstring = ()=> new Tag(TagClass.Universal, 4);
        public static readonly Func<Tag> Null = ()=> new Tag(TagClass.Universal, 5);
        public static readonly Func<Tag> ObjectIdentifier = ()=> new Tag(TagClass.Universal, 6);
        public static readonly Func<Tag> ObjectDescriptor = ()=> new Tag(TagClass.Universal, 7);
        public static readonly Func<Tag> External = ()=> new Tag(TagClass.Universal, 8);
        public static readonly Func<Tag> InstanceOf = ()=> new Tag(TagClass.Universal, 8);
        public static readonly Func<Tag> Real = ()=> new Tag(TagClass.Universal, 9);
        public static readonly Func<Tag> Enumerated = ()=> new Tag(TagClass.Universal, 10);
        public static readonly Func<Tag> EmbeddedPdv = ()=> new Tag(TagClass.Universal, 11);
        public static readonly Func<Tag> UTF8String = ()=> new Tag(TagClass.Universal, 12);
        public static readonly Func<Tag> RelativeObjectIdentifier = ()=> new Tag(TagClass.Universal, 13);
        public static readonly Func<Tag> Time = ()=> new Tag(TagClass.Universal, 14);
        public static readonly Func<Tag> ReservedForFutureEditions = ()=> new Tag(TagClass.Universal, 15);
        public static readonly Func<Tag> Sequence = ()=> new Tag(TagClass.Universal, 16);
        public static readonly Func<Tag> SequenceOf = ()=> new Tag(TagClass.Universal, 16);
        public static readonly Func<Tag> Set = ()=> new Tag(TagClass.Universal, 17);
        public static readonly Func<Tag> SetOf = ()=> new Tag(TagClass.Universal, 17);
        public static readonly Func<Tag> NumericString = ()=> new Tag(TagClass.Universal, 18);
        public static readonly Func<Tag> PrintableString = ()=> new Tag(TagClass.Universal, 19);
        public static readonly Func<Tag> TeletexString = ()=> new Tag(TagClass.Universal, 20);
        public static readonly Func<Tag> VideotexString = ()=> new Tag(TagClass.Universal, 21);
        public static readonly Func<Tag> IA5String = ()=> new Tag(TagClass.Universal, 22);
        public static readonly Func<Tag> GraphicString = ()=> new Tag(TagClass.Universal, 25);
        public static readonly Func<Tag> VisibleString = ()=> new Tag(TagClass.Universal, 26);
        public static readonly Func<Tag> GeneralString = ()=> new Tag(TagClass.Universal, 27);
        public static readonly Func<Tag> UniversalString = ()=> new Tag(TagClass.Universal, 28);
        public static readonly Func<Tag> CharacterString_29 = ()=> new Tag(TagClass.Universal, 29);
        public static readonly Func<Tag> BMPString = ()=> new Tag(TagClass.Universal, 30);
        public static readonly Func<Tag> UTCTime = ()=> new Tag(TagClass.Universal, 23);
        public static readonly Func<Tag> GeneralizedTime = ()=> new Tag(TagClass.Universal, 24);
        public static readonly Func<Tag> Date = ()=> new Tag(TagClass.Universal, 31);
        public static readonly Func<Tag> TimeOfDay = ()=> new Tag(TagClass.Universal, 32);
        public static readonly Func<Tag> DateTime = ()=> new Tag(TagClass.Universal, 33);
        public static readonly Func<Tag> Duration = ()=> new Tag(TagClass.Universal, 34);
        public static readonly Func<Tag> OIDInternationalizedResourceIdentifier = ()=> new Tag(TagClass.Universal, 35);
        public static readonly Func<Tag> RelativeOIDInternationalizedResourceIdentifier = ()=> new Tag(TagClass.Universal, 36);
        public static readonly Func<Tag> RESERVED_37_AND_MORE = ()=> new Tag(TagClass.Universal, 37);*/
