using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Standards.X509.Model;
using System;

namespace Arctium.Standards.PKCS8.v12.ASN1
{
    internal class PrivateKeyInfoModel
    {
        public Integer Version;
        public AlgorithmIdentifierModel PrivateKeyAlgorithmIdentifier;
        public OctetString PrivateKey;
        public object[] Attributes_notsupportednow { get { throw new NotSupportedException("todo implement"); } }
    }
}
