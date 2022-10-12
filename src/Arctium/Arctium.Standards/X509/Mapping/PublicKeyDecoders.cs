﻿using System;
using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Serialization.X690;
using Arctium.Standards.ASN1.Serialization.X690.DER;
using Arctium.Standards.ASN1.Standards.X509.Mapping;
using Arctium.Standards.X509.Mapping.OID;
using Arctium.Standards.X509.X509Cert;
using Arctium.Standards.X509.X509Cert.Algorithms;

namespace Arctium.Standards.ASN1.Standards.X509.Mapping
{
    class PublicKeyDecoders
    {
        X690Validation valid;
        DerDeserializer der;

        public PublicKeyDecoders()
        {
            valid = new X690Validation(nameof(PublicKeyDecoders));
            der = new DerDeserializer();
        }

        internal EcpkParameters ECPublicKeyParms(byte[] ecParamsBytes)
        {
            var node = der.Deserialize(ecParamsBytes)[0];
            // validates, 3 possible cases of CHOICE type
            valid.AnyTags(node, BuildInTag.Null, BuildInTag.ObjectIdentifier, BuildInTag.Sequence);

            if (node.TagEqual(BuildInTag.Null)) return EcpkParameters.CreateImplicitlyCA();
            else if (node.TagEqual(BuildInTag.ObjectIdentifier))
            {
                // named curve case
                ObjectIdentifier namedCurveOid = DerDecoders.DecodeWithoutTag<ObjectIdentifier>(node);
                NamedCurve curve = X509Oid.Get<NamedCurve>(namedCurveOid);

                return new EcpkParameters(curve);
            }
            else if (node.TagEqual(BuildInTag.Sequence))
            {
                throw new NotSupportedException("todo implement");
                // ecParameters case 
            }
            else
            {
                // not fund, error
            }

            throw new NotSupportedException("publickeynodedecoder not supported ecpoublicjeyparams");
        }

        internal object RSAPublicKey(byte[] keyRawValue)
        {
            var node = der.Deserialize(keyRawValue)[0];
            valid.CLength(node, 2);
            valid.Tag(node[0], BuildInTag.Integer);
            valid.Tag(node[1], BuildInTag.Integer);

            byte[] n = DerDecoders.DecodeWithoutTag<Integer>(node[0]).BinaryValue;
            byte[] e = DerDecoders.DecodeWithoutTag<Integer>(node[1]).BinaryValue;

            return new RSAPublicKey(n, e);
        }

        internal object ECPublicKey(byte[] keyRawValue)
        {
            return keyRawValue;
        }
    }
}
