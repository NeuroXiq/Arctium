using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.X690v2.DER;
using Arctium.Cryptography.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using System;

namespace Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690Decoders.Extensions
{
    public class GeneralNamesDecoder
    {
        public GeneralName DecodeGeneralName(DerTypeDecoder decoder, DerDecoded decoded)
        {
            long number = decoded.Tag.Number;
            GeneralName decodedGeneralName;
            // choice  [0 - 8], EXPLICIT tags
            switch (number)
            {
                case 6:
                    decodedGeneralName = DecodeURI(decoder, decoded);
                    break;
                case 2:
                    decodedGeneralName = DecodeDnsName(decoder, decoded);
                    break;
                default:
                    throw new NotSupportedException("Not supported decoding for GeneralName (X590) for number " + number);
            }

            return decodedGeneralName;
        }


        private GeneralName DecodeURI(DerTypeDecoder decoder,  DerDecoded decoded)
        {
            IA5String ia5String = decoder.IA5String(decoded);
            GeneralName uriGeneralName = new GeneralName(GeneralNameType.UniformResourceIdentifier, ia5String);

            return uriGeneralName;
        }



        public GeneralName DecodeDnsName(DerTypeDecoder decoder, DerDecoded decoded)
        {
            string dnsName = decoder.IA5String(decoded);
            return new GeneralName(GeneralNameType.DNSName, dnsName);
        }
    }
}



// something not work, need rewrite, 
// tags shall be explicit
//public GeneralName DecodeOtherName(X690DecodedNode otherNameSequence)
//{

//    byte[] innerContent;
//    ObjectIdentifier oid;

//    var oidNode = otherNameSequence[0];
//    var expValueNode = otherNameSequence[1];


//    oid = DerDecoders.DecodeWithoutTag<ObjectIdentifier>(oidNode);

//    int innerContentLength = (int)otherNameSequence[1].ContentLength;
//    innerContent = new byte[innerContentLength];

//    ByteBuffer.Copy(otherNameSequence.DataBuffer, otherNameSequence.ContentOffset, innerContent, 0, innerContentLength);

//    OtherName otherName = new OtherName(oid, innerContent);
//    GeneralName generalName = new GeneralName(GeneralNameType.OtherName, otherName);

//    return generalName;
//}