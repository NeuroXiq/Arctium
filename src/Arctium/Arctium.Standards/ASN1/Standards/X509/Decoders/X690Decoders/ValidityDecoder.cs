using Arctium.Standards.ASN1.ObjectSyntax.Types;
using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Serialization.X690;
using Arctium.Standards.ASN1.Serialization.X690.DER;
using Arctium.Standards.ASN1.Serialization.X690v2.DER;
using Arctium.Standards.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders;
using Arctium.Standards.ASN1.Standards.X509.Exceptions;
using Arctium.Standards.ASN1.Standards.X509.Model;
using Arctium.Standards.ASN1.Standards.X509.X509Cert;
using System;

namespace Arctium.Standards.ASN1.Standards.X509.NodeDecoders.X690NodeDecoders
{
    public class ValidityDecoder
    {
        public Validity Decode(DerTypeDecoder decoder, DerDecoded decoded)
        {
            if (decoded.ConstructedCount != 2)
            {
                throw new X509DecodingException("Invalid constructed count of the 'Validity'");
            }

            DateTime from = DecodeTime(decoder, decoded[0]);
            DateTime to = DecodeTime(decoder, decoded[1]);

            return new Validity(from, to);
        }

        private DateTime DecodeTime(DerTypeDecoder decoder, DerDecoded decoded)
        {
            Tag tag = decoded.Tag;
            if (tag == BuildInTag.UTCTime)
            {
                return (DateTime)decoder.UTCTime(decoded);
            }
            else if (tag == BuildInTag.GeneralizedTime)
            {
                return (DateTime)decoder.GeneralizedTime(decoded);
            }
            else
            {
                throw new X509DecodingException("Invalid Tag value of the time in validity sequence");
            }
        }
    }
}
