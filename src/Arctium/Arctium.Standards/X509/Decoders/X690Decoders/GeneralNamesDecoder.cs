using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Serialization.X690v2.DER;
using Arctium.Standards.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders;
using Arctium.Standards.X509.X509Cert.GenName;
using System;
using System.Collections.Generic;

namespace Arctium.Standards.ASN1.Standards.X509.Decoders.X690Decoders
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
                case 1: decodedGeneralName = new GeneralName(GeneralNameType.Rfc822Name, decoder.IA5String(decoded).Value); break;
                case 2: decodedGeneralName = new GeneralName(GeneralNameType.DNSName, decoder.IA5String(decoded).Value); break;
                case 0: throw new NotSupportedException("decodersneeded"); break;
                case 6: decodedGeneralName = new GeneralName(GeneralNameType.UniformResourceIdentifier, decoder.IA5String(decoded).Value); break;
                case 7: decodedGeneralName = new GeneralName(GeneralNameType.IPAddress, decoder.OctetString(decoded).Value); break;
                case 3:
                case 4:
                case 5:
                case 8:
                default:
                    throw new NotSupportedException("Not supported decoding for GeneralName (X590) for number " + number);
            }

            return decodedGeneralName;
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