using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.X690;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Standards.X509.Mapping.OID;
using Arctium.Cryptography.ASN1.Standards.X509.Model;

using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions;
using System;
using System.Collections.Generic;

namespace Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690NodeDecoders.ExtensionDecoders
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
                Console.WriteLine(model.ExtId);
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
        public static GeneralName[] DecodeGeneralNames(X690DecodedNode sequenceOfGeneralNames)
        {
            List<GeneralName> decodedNames = new List<GeneralName>();
            foreach (var node in sequenceOfGeneralNames)
            {
                var decoded = generalNamesDecoder.DecodeGeneralName(node);
                decodedNames.Add(decoded);
            }

            return decodedNames.ToArray();
        }
        public static GeneralName DecodeGeneralName(X690DecodedNode generalNameNode)
        {
            return generalNamesDecoder.DecodeGeneralName(generalNameNode);
        }

    }
}

/*
throw new KeyNotFoundException($"{nameof(ExtensionsDecoder)}: " + 
$"ExtensionType of {nameof(model)} parameter not found in decoding functions dictionary. " +
$"Enumerated ExtensionType (not found): {type.ToString()}. " +
$"CertificateModel OID: {model.ExtId.ToString()} ");
*/
