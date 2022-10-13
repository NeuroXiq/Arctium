using Arctium.Standards.ASN1.Serialization.X690;
using Arctium.Standards.ASN1.Serialization.X690v2.DER;
using Arctium.Standards.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders;
using Arctium.Standards.ASN1.Standards.X509.Mapping.OID;
using Arctium.Standards.ASN1.Standards.X509.Model;
using Arctium.Standards.X509.X509Cert;
using Arctium.Standards.X509.X509Cert.Extensions;
using Arctium.Standards.X509.X509Cert.GenName;
using System.Collections.Generic;

namespace Arctium.Standards.ASN1.Standards.X509.Decoders.X690Decoders.Extensions
{
    class ExtensionsDecoder
    {
        // extension value to function
        Dictionary<ExtensionType, IExtensionDecoder> map;

        static GeneralNamesDecoder generalNamesDecoder = new GeneralNamesDecoder();

        public ExtensionsDecoder()
        {
            map = new Dictionary<ExtensionType, IExtensionDecoder>();
            InitializeDictionaryMap();
        }

        public CertificateExtension MapModelToExtension(ExtensionModel model)
        {
            IExtensionDecoder extensionDecoder;

            if (!ExtensionTypeOidMap.Contains(model.ExtId))
            {
                // if specific decoder not found,
                // create 'unknown' decoder, results of decoding is 
                // just a object which contains raw bytes of certificate 

                extensionDecoder = map[ExtensionType.Unknown];
            }
            else
            {
                ExtensionType type = ExtensionTypeOidMap.Get(model.ExtId);
                extensionDecoder = map[type];
            }

            CertificateExtension mapped = extensionDecoder.DecodeExtension(model);

            return mapped;
        }

        private void InitializeDictionaryMap()
        {
            map[ExtensionType.Unknown] = new UnknownExtensionDecoder();
            
            // X509 standard extensions

            map[ExtensionType.AuthorityKeyIdentifier] = new AuthorityKeyIdentifierDecoder();
            map[ExtensionType.SubjectKeyIdentifier] = new SubjectKeyIdentifierDecoder();
            map[ExtensionType.SubjectAltName] = new SubjectAltNameDecoder();
            map[ExtensionType.KeyUsage] = new KeyUsageDecoder();
            map[ExtensionType.ExtendedKeyUsage] = new ExtendedKeyUsageDecoder();
            map[ExtensionType.CRLDistributionPoints] = new CRLDistributionPointsDecoder();
            map[ExtensionType.CertificatePolicy] = new CertificatePolicyDecoder();
            map[ExtensionType.AuthorityInfoAccess] = new AuthorityInfoAccessDecoder();
            map[ExtensionType.BasicConstraints] = new BasicConstraintsDecoder();

            // other ()
            map[ExtensionType.SCTL] = new SCTLDecoder();
            

            //[ExtensionType.KeyIdentifier] = null;
            //[ExtensionType.BasicConstraint
            //[ExtensionType.NameConstraint
            //[ExtensionType.InhibitAntipolicy
            
            //[ExtensionType.KeyUsage,
            //[ExtensionType.Authority,
            //[ExtensionType.Policy,

        }

        /// <summary>
        /// Returns decoded general names from X690decoded node 
        /// </summary>
        /// <param name="x690DecodedNode">Constructed node ('SEQUECE') which contains <br/> 
        /// encoded general name values as a implicitly tagged CHOICE [0-8 tag number]
        /// </param>
        /// <returns>Decoded general name list</returns>
        public static GeneralName[] DecodeGeneralNames(DerTypeDecoder decoder, DerDecoded sequenceOfGeneralNames)
        {
            List<GeneralName> decodedNames = new List<GeneralName>();
            foreach (var node in sequenceOfGeneralNames)
            {
                var decoded = generalNamesDecoder.DecodeGeneralName(decoder, node);
                decodedNames.Add(decoded);
            }

            return decodedNames.ToArray();
        }
        public static GeneralName DecodeGeneralName(DerTypeDecoder decoder, DerDecoded decoded)
        {
            return generalNamesDecoder.DecodeGeneralName(decoder, decoded);
        }

    }
}

/*
throw new KeyNotFoundException($"{nameof(ExtensionsDecoder)}: " + 
$"ExtensionType of {nameof(model)} parameter not found in decoding functions dictionary. " +
$"Enumerated ExtensionType (not found): {type.ToString()}. " +
$"CertificateModel OID: {model.ExtId.ToString()} ");
*/
