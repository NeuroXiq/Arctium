using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.X690;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Standards.X509.Types;
using Arctium.Shared.Helpers.Buffers;
using System;
using System.Collections.Generic;

namespace Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690NodeDecoders.ExtensionDecoders
{
    public class GeneralNamesDecoder
    {
        public GeneralName[] DecodeGeneralNames(X690DecodedNode gnameNodes)
        {
            var sequence = gnameNodes;
            List<GeneralName> decoded = new List<GeneralName>();

            foreach (var node in sequence)
            {
                long number = node.Frame.TagNumber;
                GeneralName decodedGeneralName;
                // choice  [0 - 8], EXPLICIT tags
                switch (number)
                {
                    case 6:
                        decodedGeneralName = DecodeURI(node);
                        break;
                    case 2:
                        decodedGeneralName = DecodeDnsName(node);
                        break;
                    default:
                        throw new NotSupportedException("Not supported decoding for GeneralName (X590) for number " + number);
                }

                decoded.Add(decodedGeneralName);
            }

            return decoded.ToArray();
        }

        private GeneralName DecodeURI(X690DecodedNode node)
        {
            string ia5String = DerDecoders.DecodeWithoutTag<IA5String>(node);
            GeneralName uriGeneralName = new GeneralName(GeneralNameType.UniformResourceIdentifier, ia5String);

            return uriGeneralName;
        }



        public GeneralName DecodeDnsName(X690DecodedNode node)
        {
            string dnsName = DerDecoders.DecodeWithoutTag<IA5String>(node);
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