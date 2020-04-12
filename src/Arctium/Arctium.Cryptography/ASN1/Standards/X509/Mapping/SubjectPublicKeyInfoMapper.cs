using System;
using System.Collections.Generic;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Standards.X509.Exceptions;
using Arctium.Cryptography.ASN1.Standards.X509.Mapping.OID;
using Arctium.Cryptography.ASN1.Standards.X509.Model;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using static Arctium.Cryptography.ASN1.Standards.X509.X509Cert.PublicKeyAlgorithm;

namespace Arctium.Cryptography.ASN1.Standards.X509.Mapping
{
    //
    //- -
    // mapping require decoding of public key values.
    // this class 'switchs' to valid decode implemented in publicKeynodedecoder
    // but right before, deserializes ber-encoded structure
    //


    class SubjectPublicKeyInfoMapper
    {
        static HashSet<PublicKeyAlgorithm> parmsMustBeNull = new HashSet<PublicKeyAlgorithm>()
        {
            RSAEncryption, 
        };


        PublicKeyDecoders decoders;
        DerDeserializer der;

        public SubjectPublicKeyInfoMapper()
        {
            decoders = new PublicKeyDecoders();
            der = new DerDeserializer();
        }

        internal SubjectPublicKeyInfo Map(SubjectPublicKeyInfoModel subjectPublicKeyInfo)
        {
            AlgorithmIdentifierModel algoModel = subjectPublicKeyInfo.Algorithm;
            ObjectIdentifier algoOid = algoModel.Algorithm;
            byte[] algoParms = algoModel.EncodedParameters;
            byte[] publicKey = subjectPublicKeyInfo.SubjectPublicKey.Value;

            PublicKeyAlgorithm algorithm = PublicKeyAlgorithmOidMap.Get(algoOid);
            object mappedParms = MapParms(algorithm, algoParms);
            object mappedPublicKey = MapPublicKey(algorithm, publicKey);


            return new SubjectPublicKeyInfo(algorithm, mappedParms, mappedPublicKey);
        }

        private object MapPublicKey(PublicKeyAlgorithm algorithm, byte[] keyRawValue)
        {
            switch (algorithm)
            {
                case RSAEncryption: return decoders.RSAPublicKey(keyRawValue);
                case ECPublicKey: return decoders.ECPublicKey(keyRawValue);
                default: break;
            }

            throw new NotSupportedException(
                    "SubjectPubliKeyInfoMapper not support maping for this type of public key: " +
                    algorithm.ToString());
        }

        private object MapParms(PublicKeyAlgorithm algorithm, byte[] algoParms)
        {
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
                case ECPublicKey: return decoders.ECPublicKeyParms(algoParms);
                default: break;
            }

            throw new NotSupportedException($"SubjectPUblicKeyInfoMapper not supports: {algorithm}");
        }
    }
}
