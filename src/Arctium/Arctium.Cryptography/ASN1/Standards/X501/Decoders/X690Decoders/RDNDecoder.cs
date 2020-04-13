using Arctium.Cryptography.ASN1.ObjectSyntax.Types;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.Exceptions;
using Arctium.Cryptography.ASN1.Serialization.X690;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Serialization.X690v2.DER;
using Arctium.Cryptography.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders;
using Arctium.Cryptography.ASN1.Standards.X501.Mapping.Oid;
using X501N = Arctium.Cryptography.ASN1.Standards.X501.Types.Name;
using System.Collections.Generic;
using Arctium.Cryptography.ASN1.Standards.X501.Types;
using System;

namespace Arctium.Cryptography.ASN1.Standards.X501.Decoders.X690Decoders
{
    public class RDNDecoder
    {
        
        /// <summary>
        /// Decodes  to <see cref="RelativeDistinguishedName"/> which is represented in param
        /// as a SET-OF { SEQUENCE : <see cref="AttributeTypeAndValue"/> } values
        /// </summary>
        /// <returns></returns>
        public RelativeDistinguishedName Decode(DerTypeDecoder decoder, DerDecoded decoded)
        {
            List<AttributeTypeAndValue> decodedList = new List<AttributeTypeAndValue>();
            foreach (var sequenceAt in decoded)
            {
                var atv = DecodeATSequence(decoder, sequenceAt);
                decodedList.Add(atv);
            }

            RelativeDistinguishedName decodedRdn = new RelativeDistinguishedName(decodedList.ToArray());

            return decodedRdn;
        }

        public static AttributeTypeAndValue DecodeATSequence(DerTypeDecoder decoder, DerDecoded decoded)
        {
            var typeNode =  decoded[0];
            var valueNode = decoded[1];
            Tag valueTag =  decoded[1].Tag;

            ObjectIdentifier typeOid = decoder.ObjectIdentifier(decoded[0]);
            object value;
            AttributeType type;

            if (!AttributeTypeOidMap.Exists(typeOid))
            {
                type = AttributeType.Unknown;
                byte[] rawValue = DerDecoderHelper.GetBytes(decoder.Buffer, valueNode);

                value = new UnknownAttributeTypeAndValue(typeOid, rawValue);
                return new AttributeTypeAndValue(type, value);
            }

            type = AttributeTypeOidMap.Get(typeOid);

            if (valueTag == BuildInTag.PrintableString)
            {
                value = decoder.PrintableString(decoded[1]);
            }
            else if (valueTag == BuildInTag.UTF8String)
            {
                value = decoder.UTF8String(decoded[1]);
            }
            else if (valueTag == BuildInTag.UniversalString)
            {
                value = decoder.UniversalString(decoded[1]);
            }
            else
            {
                throw new X690DecoderException("Current tag for value of the AttributeTypeAndValue are invalid or not supported by this implementation. " + valueTag.ToString());
            }

            return new AttributeTypeAndValue(type, value);

        }
    }
}
