using Arctium.Cryptography.ASN1.ObjectSyntax.Types;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.X690;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Standards.X509.Exceptions;
using Arctium.Cryptography.ASN1.Standards.X509.Model;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using System;

namespace Arctium.Cryptography.ASN1.Standards.X509.NodeDecoders.X690NodeDecoders
{
    public class ValidityNodeDecoder : IX690NodeDecoder<Validity>
    {
        public Validity Decode(X690DecodedNode node)
        {
            DateTime from = DecodeTime(node[0]);
            DateTime to = DecodeTime(node[1]);

            return new Validity(from, to);
        }

        private DateTime DecodeTime(X690DecodedNode timeNode)
        {
            Tag tag = timeNode.Frame.Tag;
            if (tag == BuildInTag.UTCTime)
            {
                return (DateTime)DerDecoders.DecodeWithTag<UTCTime>(timeNode).Value;
            }
            else if (tag == BuildInTag.GeneralizedTime)
            {
                return (DateTime)DerDecoders.DecodeWithTag<GeneralizedTime>(timeNode).Value;
            }
            else
            {
                throw new X509DecodingException("Invalid Tag value of the time in validity sequence");
            }
        }
    }
}
