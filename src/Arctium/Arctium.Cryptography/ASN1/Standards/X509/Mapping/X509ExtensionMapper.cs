using System;
using System.Collections.Generic;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Standards.X509.Mapping.OID;
using Arctium.Cryptography.ASN1.Standards.X509.Model;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;

/* - Class info -
 * 
 * This is a map from intermediate 'ExtensionModel' object to 'Extension' object
 *   
 * Performs mapping from the 'ExtensionModel' to the 'Extension'. Is also makes sure, that internal 
 * *REPRESENTATION (Structure)* of an every supported extension is valid (otherwise mapping cannot be done).
 * Extension values are mapped from raw 'octetstring' (byte array) to typed objects.
 *  
 * */


namespace Arctium.Cryptography.ASN1.Standards.X509.Mapping
{

    public static class X509ExtensionMapper
    {
        // extension value to function
        static Dictionary<ExtensionType, Func<ExtensionModel, CertificateExtension>> map;

        // Resources
        

        static X509ExtensionMapper()
        {
            map = new Dictionary<ExtensionType, Func<ExtensionModel, CertificateExtension>>();
            InitializeDictionaryMap();
        }

        

        public static CertificateExtension MapModelToExtension(ExtensionModel model)
        {
            ExtensionType type = ExtensionTypeOidMap.Get(model.ExtId);
            var func = map[type];
            CertificateExtension mapped = func(model);

            return mapped;
        }

        static void MapCommon(ExtensionModel model, out ExtensionType type, out bool isCritical)
        {
            type = ExtensionTypeOidMap.Get(model.ExtId);
            isCritical = model.Critical;
        }

        private static void InitializeDictionaryMap()
        {
            map[ExtensionType.AuthorityKeyIdentifier] = AuthorityKeyIdentifierFunc;
        }

        private static CertificateExtension AuthorityKeyIdentifierFunc(ExtensionModel model)
        {
           
            throw new NotImplementedException();
        }
    }
}
