using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.X690;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Standards.X509.Mapping.OID;
using Arctium.Cryptography.ASN1.Standards.X509.Model;
using Arctium.Cryptography.ASN1.Standards.X509.Types;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using System;
using System.Collections.Generic;

namespace Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690NodeDecoders.ExtensionDecoders
{
    public class ExtensionsDecoder
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
            ExtensionType type = ExtensionTypeOidMap.Get(model.ExtId);

            if (!map.ContainsKey(type))
            {
                throw new KeyNotFoundException($"{nameof(ExtensionsDecoder)}: " + 
                    $"ExtensionType of {nameof(model)} parameter not found in decoding functions dictionary. " +
                    $"Enumerated ExtensionType (not found): {type.ToString()}. " +
                    $"model OID: {model.ExtId.ToString()} ");
            }

            var extensionDecoder = map[type];
            CertificateExtension mapped = extensionDecoder.DecodeExtension(model);

            return mapped;
        }

        static void MapCommon(ExtensionModel model, out ExtensionType type, out bool isCritical)
        {
            type = ExtensionTypeOidMap.Get(model.ExtId);
            isCritical = model.Critical;
        }

        private void InitializeDictionaryMap()
        {
           map[ExtensionType.AuthorityKeyIdentifier] = new AuthorityKeyIdentifierDecoder();
           map[ExtensionType.SubjectKeyIdentifier] = new SubjectKeyIdentifierDecoder();
           map[ExtensionType.SubjectAltName] = new SubjectAltNameDecoder();
           map[ExtensionType.KeyUsage] = new KeyUsageDecoder();
           map[ExtensionType.ExtendedKeyUsage] = new ExtendedKeyUsageDecoder();
           map[ExtensionType.CRLDistributionPoints] = new CRLDistributionPointsDecoder();
        }

        /// <summary>
        /// Returns decoded general names from X690decoded node 
        /// </summary>
        /// <param name="x690DecodedNode">Constructed node ('SEQUECE') which contains <br/> 
        /// encoded general name values as a implicitly tagged CHOICE [0-8 tag number]
        /// </param>
        /// <returns>Decoded general name list</returns>
        public static GeneralName[] DecodeGeneralNames(X690DecodedNode x690DecodedNode)
        {
            return generalNamesDecoder.DecodeGeneralNames(x690DecodedNode);
        }
    }
}
