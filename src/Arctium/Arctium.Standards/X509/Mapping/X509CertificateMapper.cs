using System;
using System.Collections.Generic;
using System.Linq;
using Arctium.Cryptography.Utils;
using Arctium.Standards.ASN1.Serialization.X690v2.DER;
using Arctium.Standards.ASN1.Standards.X509.Decoders.X690Decoders.Extensions;
using Arctium.Standards.ASN1.Standards.X509.Model;
using Arctium.Standards.X509.Mapping.OID;
using Arctium.Standards.X509.X509Cert;
using Arctium.Standards.X509.X509Cert.Algorithms;
using Arctium.Standards.X509.X509Cert.Extensions;

/*
 * Mapper from certificate model to X509Certificate object
 * 
 * Performs mapping from 'raw' certificate model to X509Certificate object
 * 
 */


namespace Arctium.Standards.ASN1.Standards.X509.Mapping
{
    public class X509CertificateMapper
    {
        SubjectPublicKeyInfoMapper subjectPublicKeyInfoMapper;
        ExtensionsDecoder extensionDecoders = new ExtensionsDecoder();

        public X509CertificateMapper()
        {
            subjectPublicKeyInfoMapper = new SubjectPublicKeyInfoMapper();
        }

        public X509Certificate MapFromModel(X509CertificateModel modelObject)
        {
            X509Certificate cert = new X509Certificate();
            TBSCertificate tbs = modelObject.TBSCertificate;

            cert.Version = (int)tbs.Version.ToULong();
            cert.SerialNumber = tbs.SerialNumber.BinaryValue;
            cert.Issuer = tbs.Issuer;
            cert.ValidNotBefore = tbs.Validity.NotBefore;
            cert.ValidNotAfter = tbs.Validity.NotAfter;
            cert.Subject = tbs.Subject;
            cert.IssuerUniqueId =  tbs.IssuerUniqueId.Value;
            cert.SubjectUniqueId = tbs.SubjectUniqueId.Value;
            cert.Extensions = MapExtensions(modelObject.TBSCertificate.Extensions);
            cert.SubjectPublicKeyInfo = subjectPublicKeyInfoMapper.Map(modelObject.TBSCertificate.SubjectPublicKeyInfo);

            MapSignature(modelObject, out var signAlgoIdentif, out var sigValue);

            cert.SignatureAlgorithm = signAlgoIdentif;
            cert.SignatureValue = sigValue;

            return cert;
        }

        private static void MapSignature(X509CertificateModel model, out SignatureAlgorithmIdentifier signAlgoIden, out SignatureValue sigValue)
        {
            var sigOid = model.SignatureAlgorithm.Algorithm;
            var sigParams = model.SignatureAlgorithm.EncodedParameters;
            var sigBytes = model.SignatureValue.Value;

            signAlgoIden = null; sigValue = null;

            SignatureAlgorithmType signatureAlgoType = X509Oid.Get<SignatureAlgorithmType>(sigOid);
            object signatueValueObject = null;
            SignatureValueType signatueValueType = SignatureValueType.NotDefined_RawBytes;
            SignatureAlgorithmParameters parms = null;

            if (sigParams != null) throw new NotImplementedException("TODO: action not implemented/supported (signature algorithm parameters must be null for now)");

            parms = null;

            var info = signaturesInfo.Single(info => info.SignatureAlgorithmType == signatureAlgoType);
            signatueValueType = info.SignatureValueType;

            // Decode Signature Bytes if needed ('signatureValue' in x509 rfc)
            if (signatueValueType == SignatureValueType.NotDefined_RawBytes)
            {
                signatueValueObject = sigBytes;
            }
            else if (signatueValueType == SignatureValueType.EcdsaSigValue)
            {
                // SEQUENCE :== { r INTEGER, s INTEGER }

                var decodingContext = DerDeserializer.Deserialize2(sigBytes, 0);

                byte[] rBytes = decodingContext.DerTypeDecored.Integer(decodingContext.Current[0]).BinaryValue;
                byte[] sBytes = decodingContext.DerTypeDecored.Integer(decodingContext.Current[1]).BinaryValue;

                signatueValueObject = new EcdsaSigValue(rBytes, sBytes);
            }
            else throw new NotSupportedException();

            signAlgoIden = new SignatureAlgorithmIdentifier(signatureAlgoType, parms);
            sigValue = new SignatureValue(signatueValueType, signatueValueObject);
        }

        struct SignatureAlgoInfo
        {
            public SignatureAlgorithmType SignatureAlgorithmType;
            public SignatureValueType SignatureValueType;

            public SignatureAlgoInfo(SignatureAlgorithmType type, SignatureValueType signatureValueType)
            {
                SignatureAlgorithmType = type;
                SignatureValueType = signatureValueType;
            }
        }

        static SignatureAlgoInfo[] signaturesInfo = new SignatureAlgoInfo[]
        {
            new SignatureAlgoInfo(SignatureAlgorithmType.SHA1WithRSAEncryption, SignatureValueType.NotDefined_RawBytes),
            new SignatureAlgoInfo(SignatureAlgorithmType.SHA224WithRSAEncryption, SignatureValueType.NotDefined_RawBytes),
            new SignatureAlgoInfo(SignatureAlgorithmType.SHA384WithRSAEncryption, SignatureValueType.NotDefined_RawBytes),
            new SignatureAlgoInfo(SignatureAlgorithmType.SHA512WithRSAEncryption, SignatureValueType.NotDefined_RawBytes),
            new SignatureAlgoInfo(SignatureAlgorithmType.SHA256WithRSAEncryption, SignatureValueType.NotDefined_RawBytes),
            new SignatureAlgoInfo(SignatureAlgorithmType.MD2WithRSAEncryption, SignatureValueType.NotDefined_RawBytes),
            new SignatureAlgoInfo(SignatureAlgorithmType.MD5WithRSAEncryption, SignatureValueType.NotDefined_RawBytes),

            // EcdsaSigValue
            new SignatureAlgoInfo(SignatureAlgorithmType.ECDSAWithSHA224, SignatureValueType.EcdsaSigValue),
            new SignatureAlgoInfo(SignatureAlgorithmType.ECDSAWithSHA256, SignatureValueType.EcdsaSigValue),
            new SignatureAlgoInfo(SignatureAlgorithmType.ECDSAWithSHA384, SignatureValueType.EcdsaSigValue),
            new SignatureAlgoInfo(SignatureAlgorithmType.ECDSAWithSHA512, SignatureValueType.EcdsaSigValue),
        };

        private CertificateExtension[] MapExtensions(ExtensionModel[] extensions)
        {
            List<CertificateExtension> mappedExtensions = new List<CertificateExtension>();
            foreach (var model in extensions)
            {
                var mapped = extensionDecoders.MapModelToExtension(model);
                mappedExtensions.Add(mapped);
            }

            return mappedExtensions.ToArray();
        }
    }
}
