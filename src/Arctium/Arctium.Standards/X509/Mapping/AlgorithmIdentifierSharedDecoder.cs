using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Serialization.X690;
using Arctium.Standards.ASN1.Serialization.X690.DER;
using Arctium.Standards.X509.X509Cert;
using System;

namespace Arctium.Standards.ASN1.Standards.X509.Mapping
{
    /*
     *  public key/signature algorihms can have same 
     *  parameters encoded in same way.
     */


    class AlgorithmIdentifierSharedDecoder
    {
        X690Validation valid = new X690Validation(nameof(AlgorithmIdentifierSharedDecoder));
        DerDeserializer der = new DerDeserializer();
        public AlgorithmIdentifierSharedDecoder()
        {

        }

        internal EcpkParameters ECPublicKeyParms(byte[] ecParamsBytes)
        {
            var node = der.Deserialize(ecParamsBytes)[0];
            // validates, 3 possible cases of CHOICE type
            valid.AnyTags(node, BuildInTag.Null, BuildInTag.ObjectIdentifier, BuildInTag.Sequence);

            if (node.TagEqual(BuildInTag.Null))
            {
                // implicitlyCA case
                return new EcpkParameters();
            }
            else if (node.TagEqual(BuildInTag.ObjectIdentifier))
            {
                // named curve case
                ObjectIdentifier namedCurveOid = DerDecoders.DecodeWithoutTag<ObjectIdentifier>(node);

                return new EcpkParameters(namedCurveOid);
            }
            else if (node.TagEqual(BuildInTag.Sequence))
            {
                // ecParameters case 
            }
            else
            {
                // not fund, error
            }

            throw new NotSupportedException("publickeynodedecoder not supported ecpoublicjeyparams");
        }

    }
}
