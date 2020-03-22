using System;
using System.Collections.Generic;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.Exceptions;
using Arctium.Cryptography.ASN1.Serialization.X690;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Standards.X501.Mapping.Oid;
using Arctium.Cryptography.ASN1.Standards.X501.Types;

namespace Arctium.Cryptography.ASN1.Standards.X501.Decoders.X690NodeDecoders
{
    public class NameNodeDecoder : IX690NodeDecoder<Name>
    {
        RDNNodeDecoder rdnDecoder = new RDNNodeDecoder();

        /// <summary>
        /// Decodes <see cref="Name"/> from SEQUENCE-OF relative distinguished names as inner values
        /// </summary>
        /// <param name="sequenceOfNode">SEQUENCE-OF node</param>
        /// <returns>Decoded node as <see cref="Name"/> object </returns>
        public Name Decode(X690DecodedNode sequenceOfNode)
        {
            List<RelativeDistinguishedName> decodedList = new List<RelativeDistinguishedName>();
            foreach (var setOf in sequenceOfNode)
            {
                RelativeDistinguishedName decodedRdn = rdnDecoder.Decode(setOf);
                decodedList.Add(decodedRdn);
            }

            return new Name(NameType.RDNSequence, decodedList.ToArray());
        }
    }
}
