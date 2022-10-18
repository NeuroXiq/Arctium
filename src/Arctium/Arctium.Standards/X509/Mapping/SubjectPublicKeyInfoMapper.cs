using System;
using System.Collections.Generic;
using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Serialization.X690.DER;
using Arctium.Standards.ASN1.Standards.X509.Exceptions;
using Arctium.Standards.ASN1.Standards.X509.Mapping.OID;
using Arctium.Standards.ASN1.Standards.X509.Model;
using Arctium.Standards.X509.X509Cert;
using Arctium.Standards.X509.X509Cert.Algorithms;

namespace Arctium.Standards.ASN1.Standards.X509.Mapping
{
    //
    //- -
    // mapping require decoding of public key values.
    // this class 'switchs' to valid decode implemented in publicKeynodedecoder
    // but right before, deserializes ber-encoded structure
    //


    class SubjectPublicKeyInfoMapper
    {
        static HashSet<PublicKeyAlgorithmIdentifierType> parmsMustBeNull = new HashSet<PublicKeyAlgorithmIdentifierType>()
        {
            PublicKeyAlgorithmIdentifierType.RSAEncryption, 
        };


        static PublicKeyDecoders decoders;

        static SubjectPublicKeyInfoMapper()
        {
            decoders = new PublicKeyDecoders();
        }

        internal static SubjectPublicKeyInfo Map(PublicKeyInfoModel subjectPublicKeyInfo)
        {
            byte[] publicKey = subjectPublicKeyInfo.SubjectPublicKey.Value;
            PublicKeyAlgorithmIdentifier algoIdentifier = MapAlgorithmIdentifier(subjectPublicKeyInfo.Algorithm);
            object mappedPublicKey = MapPublicKey(algoIdentifier.Algorithm, publicKey);

            var subPubKey = new SubjectPublicKeyInfoPublicKey(algoIdentifier.Algorithm, mappedPublicKey);

            return new SubjectPublicKeyInfo(algoIdentifier, subPubKey);
        }

        public static PublicKeyAlgorithmIdentifier MapAlgorithmIdentifier(AlgorithmIdentifierModel algoModel)
        {
            ObjectIdentifier algoOid = algoModel.Algorithm;
            byte[] algoParms = algoModel.EncodedParameters;

            PublicKeyAlgorithmIdentifierType algorithm = PublicKeyAlgorithmOidMap.Get(algoOid);
            PublicKeyAlgorithmIdentifierParametersType? parmsType;
            var parmsObj = MapParms(algorithm, algoParms, out parmsType);

            PublicKeyAlgorithmIdentifierParameters subParms = null;

            if (parmsType != null)
            {
                subParms = new PublicKeyAlgorithmIdentifierParameters(parmsType.Value, parmsObj);
            }

            var algoIdentifier = new PublicKeyAlgorithmIdentifier(algorithm, subParms);

            return algoIdentifier;
        }

        private static object MapPublicKey(PublicKeyAlgorithmIdentifierType algorithm, byte[] keyRawValue)
        {
            switch (algorithm)
            {
                case PublicKeyAlgorithmIdentifierType.RSAEncryption: return decoders.RSAPublicKey(keyRawValue);
                case PublicKeyAlgorithmIdentifierType.ECPublicKey: return decoders.ECPublicKey(keyRawValue);
                default: break;
            }

            throw new NotSupportedException(
                    "SubjectPubliKeyInfoMapper not support maping for this type of public key: " +
                    algorithm.ToString());
        }

        private static object MapParms(PublicKeyAlgorithmIdentifierType algorithm, byte[] algoParms, out PublicKeyAlgorithmIdentifierParametersType? type)
        {
            type = null;

            if (parmsMustBeNull.Contains(algorithm))
            {
                if (algoParms != null)
                {
                    throw new X509DecodingException(
                        "SubjectPublicKeyInfoMapper: " + 
                        $"Invalid parameters. Parameters must be null but current value is not" +
                        $"PublicKeyAlgorithmType: {algorithm}");
                }

                return null;
            }

            switch (algorithm)
            {
                case PublicKeyAlgorithmIdentifierType.ECPublicKey:
                    type = PublicKeyAlgorithmIdentifierParametersType.EcpkParameters;
                    return decoders.ECPublicKeyParms(algoParms);
                default: break;
            }

            throw new NotSupportedException($"SubjectPUblicKeyInfoMapper not supports: {algorithm}");
        }
    }
}
