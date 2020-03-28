using Arctium.Cryptography.ASN1.ObjectSyntax.Types;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.X690;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Standards.X501.Types;
using Arctium.Cryptography.ASN1.Standards.X509.Exceptions;
using Arctium.Cryptography.ASN1.Standards.X509.Model;
using Arctium.Cryptography.ASN1.Standards.X509.Types;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions;
using System;
using System.Collections.Generic;
using X501D = Arctium.Cryptography.ASN1.Standards.X501.Decoders.X690NodeDecoders;

namespace Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690NodeDecoders.ExtensionDecoders
{
    public class CRLDistributionPointsDecoder : IExtensionDecoder
    {
        DerDeserializer derDeserializer = new DerDeserializer();
        
        public CertificateExtension DecodeExtension(ExtensionModel arg)
        {
            var distribPointsSequence = derDeserializer.Deserialize(arg.ExtnValue.Value)[0];
            List<DistributionPoint> decodedDistPoints = new List<DistributionPoint>();

            //sequence of sequences
            foreach (var innerSeq in distribPointsSequence)
            {
                var decodedDistrPoint = DecodeDistributionPointNode(innerSeq);
                decodedDistPoints.Add(decodedDistrPoint);
            }

            CRLDistributionPointsExtension distPointsExtension =
                new CRLDistributionPointsExtension(arg.Critical, decodedDistPoints.ToArray());

            return distPointsExtension;
        }

        public static DistributionPoint DecodeDistributionPointNode(X690DecodedNode node)
        {
            // parameter node are a SEQUENCE
            // all values are optional, tagged IMPLICIT
            // [0] => DistributionPointName
            // [1] => Reasons flags
            // [2] => crlIssuer (GeneralNames)

            var sequence = node;

            DistributionPoint.ConstructorValues ctor = DistributionPoint.ConstructorValues.CreateEmpty();

            if (sequence.HaveCS(0))
            {
                // this is a CHOICE type, remove explicit tag
                var distribPointNameChoiceType = sequence.GetCSNode(0);
                var distribPointName = distribPointNameChoiceType[0];
                ctor.DistributionPointNameObject = DecodeCRLDistributionPointName(distribPointName, out ctor.DPNType);
                ctor.IsDistributionPointPresent = true;
            }
            if (sequence.HaveCS(1))
            {
                BitString flagsBitString = DerDecoders.DecodeWithoutTag<BitString>(node);
                ctor.IsReasonsPresent = true;
                throw new NotImplementedException();
            }
            if (sequence.HaveCS(2))
            {
                throw new NotImplementedException();
            }

            return new DistributionPoint(ctor);
        }

        public static object DecodeCRLDistributionPointName(X690DecodedNode node, out DistributionPointNameType type)
        {
            // this choice have 2 possible tags (IMPLICIT):
            // [0] => general name (overrides sequence universal tag)
            // [1] => Relative distinguished name

            type = DistributionPointNameType.FullName;

            if (node.TagEqual(Tag.ContextSpecific(0)))
            {
                // general names: Context-specific == 0
                // IMPLICIT tagged inner sequence of GeneralNanes (override SEquence:0 16 -> context-specific 0)   
                var generalNamesSequence = node;
                type = DistributionPointNameType.FullName;

                GeneralName[] generalNames = ExtensionsDecoder.DecodeGeneralNames(generalNamesSequence);
                return generalNames;

            }
            else if (node.TagEqual(Tag.ContextSpecific(1)))
            {
                // RDN: context-specific == 1
                type = DistributionPointNameType.NameRelativeToCRLIssuer;
                RelativeDistinguishedName rdn = X501D.RDNNodeDecoder.DecodeNode(node);

                return rdn;
            }
            else
            {
                // ?? 
                throw new X509DecodingException(
                    "Cannot find valid Context-Specific tag for " +
                    "DistributionPoint object in CRLDistributionPoint Extension");
            }
        }
    }
}
