using Arctium.Cryptography.ASN1.ObjectSyntax.Types;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.Exceptions;
using Arctium.Cryptography.ASN1.Serialization.X690;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Standards.X501.Mapping.Oid;
using Arctium.Cryptography.ASN1.Standards.X501.Types;
using System.Collections.Generic;

namespace Arctium.Cryptography.ASN1.Standards.X501.Decoders.X690NodeDecoders
{
    public class RDNNodeDecoder : IX690NodeDecoder<RelativeDistinguishedName>
    {
        /// <summary>
        /// Decodes <paramref name="node"/> to <see cref="RelativeDistinguishedName"/> which is represented in <paramref name="node"/> param
        /// as a SET-OF { SEQUENCE : <see cref="AttributeTypeAndValue"/> } values
        /// </summary>
        /// <param name="node">Node represents SET OF AttributeTypeAndValue </param>
        /// <returns></returns>
        public RelativeDistinguishedName Decode(X690DecodedNode node)
        {
            return DecodeNode(node);
        }

        /// <summary>
        /// Decodes <paramref name="node"/> to <see cref="RelativeDistinguishedName"/> which is represented in <paramref name="node"/> param
        /// as a SET-OF { SEQUENCE : <see cref="AttributeTypeAndValue"/> } values
        /// </summary>
        /// <param name="node">Node represents SET OF AttributeTypeAndValue </param>
        /// <returns></returns>
        public static RelativeDistinguishedName DecodeNode(X690DecodedNode node)
        {
            List<AttributeTypeAndValue> decoded = new List<AttributeTypeAndValue>();
            foreach (var sequenceAt in node)
            {
                var atv = DecodeATSequence(sequenceAt);
                decoded.Add(atv);
            }

            RelativeDistinguishedName decodedRdn = new RelativeDistinguishedName(decoded.ToArray());

            return decodedRdn;
        }

        public static AttributeTypeAndValue DecodeATSequence(X690DecodedNode node)
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
