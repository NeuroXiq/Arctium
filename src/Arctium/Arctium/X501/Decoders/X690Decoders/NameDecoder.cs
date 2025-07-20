using System.Collections.Generic;
using Arctium.Standards.ASN1.Serialization.X690v2.DER;
using Arctium.Standards.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders;
using Arctium.Standards.X501.Types;

namespace Arctium.Standards.X501.Decoders.X690Decoders
{
    public class NameDecoder
    {
        RDNDecoder rdnDecoder = new RDNDecoder();

        /// <summary>
        /// Decodes <see cref="Name"/> from SEQUENCE-OF relative distinguished names as inner values
        /// </summary>
        /// <param name="sequenceOfNode">SEQUENCE-OF node</param>
        /// <returns>Decoded node as <see cref="Name"/> object </returns>
        public Name Decode(DerTypeDecoder decoder, DerDecoded sequenceOfNode)
        {
            List<RelativeDistinguishedName> decodedList = new List<RelativeDistinguishedName>();
            foreach (var setOf in sequenceOfNode)
            {
                RelativeDistinguishedName decodedRdn = rdnDecoder.Decode(decoder, setOf);
                decodedList.Add(decodedRdn);
            }

            return new Name(NameType.RDNSequence, decodedList.ToArray());
        }
    }
}
