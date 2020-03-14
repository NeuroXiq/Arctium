using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;
using System;
using System.Collections.Generic;

namespace Arctium.Encoding.IDL.ASN1.Standards.X509.X509Certificate.Mapping
{
    /*
     * This is a mapper from ObjectIdentifier of to X509CertExtensionType enum
     * 
     * Map oid object to enum
     * 
     * This is some container for defined extensions types from raw numbers represented by Object identifier 
     * to convenient enumerated type.
     * 
     */


    public class OidToExtensionTypeMap
    {
        Dictionary<ObjectIdentifier, X509CertExtensionType> oidToExtMap;
        public OidToExtensionTypeMap()
        {
            oidToExtMap = new Dictionary<ObjectIdentifier, X509CertExtensionType>();

            InsertMappings();
        }

        private void InsertMappings()
        {
            
        }

        public X509CertExtensionType Get(ObjectIdentifier oid)
        {
            
            X509CertExtensionType value;

            if (oidToExtMap.TryGetValue(oid, out value)) return value;
            else return X509CertExtensionType.Unrecognized;
        }
    }
}
