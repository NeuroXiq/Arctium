using Arctium.Standards.ASN1.ObjectSyntax.Types;
using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Serialization.Exceptions;
using Arctium.Standards.ASN1.Serialization.X690;
using Arctium.Standards.ASN1.Serialization.X690v2.DER;
using Arctium.Standards.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders;
using Arctium.Standards.X501.Decoders.X690Decoders;
using Arctium.Standards.X501.Types;
using Arctium.Standards.ASN1.Standards.X509.Exceptions;
using Arctium.Standards.ASN1.Standards.X509.Model;
using Arctium.Standards.X509.X509Cert;
using Arctium.Standards.X509.X509Cert.Extensions;
using System;
using System.Collections.Generic;

namespace Arctium.Standards.ASN1.Standards.X509.Decoders.X690Decoders.Extensions
{
    public class CRLDistributionPointsDecoder : IExtensionDecoder
    {
        public CertificateExtension DecodeExtension(ExtensionModel arg)
        {
            var distribPointsSequence = DerDeserializer.Deserialize(arg.ExtnValue.Value, 0);
            DerTypeDecoder typeDecoder = new DerTypeDecoder(arg.ExtnValue.Value);
            List<DistributionPoint> decodedDistPoints = new List<DistributionPoint>();

            //sequence of sequences
            foreach (var innerSeq in distribPointsSequence)
            {
                var decodedDistrPoint = DecodeDistributionPointNode(typeDecoder, innerSeq);
                decodedDistPoints.Add(decodedDistrPoint);
            }

            CRLDistributionPointsExtension distPointsExtension =
                new CRLDistributionPointsExtension(arg.Critical, decodedDistPoints.ToArray());

            return distPointsExtension;
        }

        public static DistributionPoint DecodeDistributionPointNode(DerTypeDecoder decoder, DerDecoded decoded)
        {
            // parameter node are a SEQUENCE
            // all values are optional, tagged IMPLICIT
            // [0] => DistributionPointName
            // [1] => Reasons flags
            // [2] => crlIssuer (GeneralNames)

            var sequence = decoded;

            DistributionPoint.ConstructorValues ctor = DistributionPoint.ConstructorValues.CreateEmpty();

            if (sequence.ConstructedCount > 0)
            {
                DerDecoded[] values = new DerDecoded[3];
                bool[] exists = new bool[3];
                long prevNumber = -1;

                foreach (var optional in decoded)
                {
                    long curNumber = optional.Tag.Number;
                    if (curNumber > prevNumber && (curNumber >= 0 && curNumber <= 2))
                    {
                        prevNumber = curNumber;
                        values[curNumber] = optional;
                        exists[curNumber] = true;
                    }
                    else
                    {
                        throw new X690DecoderException("Invalid coding of the distributionPoints");
                    }
                }

                if (exists[0])
                {
                    // this is a CHOICE type, remove explicit tag
                    var distribPointNameChoiceType = values[0];
                    var distribPointName = distribPointNameChoiceType[0];
                    ctor.DistributionPointNameObject = DecodeCRLDistributionPointName(decoder, distribPointName, out ctor.DPNType);
                    ctor.IsDistributionPointPresent = true;
                }
                if (exists[1])
                {
                    BitString flagsBitString = decoder.BitString(values[1]);
                    ctor.IsReasonsPresent = true;
                    throw new NotImplementedException();
                }
                if (exists[2])
                {
                    throw new NotImplementedException();
                }

            }

            

            return new DistributionPoint(ctor);
        }

        public static object DecodeCRLDistributionPointName(DerTypeDecoder decoder, DerDecoded decoded, out DistributionPointNameType type)
        {
            // this choice have 2 possible tags (IMPLICIT):
            // [0] => general name (overrides sequence universal tag)
            // [1] => Relative distinguished name

            type = DistributionPointNameType.FullName;

            if (decoded.Tag == Tag.ContextSpecific(0))
            {
                // general names: Context-specific == 0
                // IMPLICIT tagged inner sequence of GeneralNanes (override SEquence:0 16 -> context-specific 0)   
                var generalNamesSequence = decoded;
                type = DistributionPointNameType.FullName;

                GeneralName[] generalNames = ExtensionsDecoder.DecodeGeneralNames(decoder, generalNamesSequence);
                return generalNames;

            }
            else if (decoded.Tag == Tag.ContextSpecific(1))
            {
                // RDN: context-specific == 1
                type = DistributionPointNameType.NameRelativeToCRLIssuer;
                RelativeDistinguishedName rdn = (new RDNDecoder()).Decode(decoder, decoded);

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
