using System;
using System.Collections.Generic;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.Exceptions;
using Arctium.Cryptography.ASN1.Serialization.X690;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Standards.X500.Mapping.Oid;
using Arctium.Cryptography.ASN1.Standards.X500.Types;

namespace Arctium.Cryptography.ASN1.Standards.X500.Decoders.X690NodeDecoders
{
    public class NameDecoder : IX690NodeDecoder<Name>
    {
        public Name Decode(X690DecodedNode sequenceOfNode)
        {
            List<AttributeTypeAndValue> decoded = new List<AttributeTypeAndValue>();
            foreach (var set in sequenceOfNode)
            {
                foreach (var sequenceAt in set)
                {
                    var atv = DecodeATSequence(sequenceAt);
                    decoded.Add(atv);
                }
            }
            return new Name(decoded.ToArray());
        }

        private AttributeTypeAndValue DecodeATSequence(X690DecodedNode node)
        {
            var typeNode = node[0];
            var valueNode = node[1];
            Tag valueTag = node[1].Frame.Tag;

            ObjectIdentifier typeOid = DerDecoders.DecodeWithoutTag<ObjectIdentifier>(node[0]);
            object value;
            AttributeType type;

            if (!AttributeTypeOidMap.Exists(typeOid))
            {
                throw new X690DecoderException("Current OID for attribute type are unrecognized or not supported. " + typeOid.ToString());
            }

            type = AttributeTypeOidMap.Get(typeOid);

            if (valueTag == BuildInTag.PrintableString)
            {
                value = DerDecoders.DecodeWithoutTag<PrintableString>(node[1]);
            }
            else if (valueTag == BuildInTag.UTF8String)
            {
                value = DerDecoders.DecodeWithoutTag<UTF8String>(node[1]);
            }
            else if (valueTag == BuildInTag.UniversalString)
            {
                value = DerDecoders.DecodeWithoutTag<UniversalString>(node[1]);
            }
            else
            {
                throw new X690DecoderException("Current tag for value of the AttributeTypeAndValue are invalid or not supported by this implementation. " + valueTag.ToString());
            }

            return new AttributeTypeAndValue(type, value);

        }
    }
}
