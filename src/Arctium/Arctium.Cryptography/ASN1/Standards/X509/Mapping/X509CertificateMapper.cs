using System.Collections.Generic;
using Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690NodeDecoders.ExtensionDecoders;
using Arctium.Cryptography.ASN1.Standards.X509.Model;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions;

/*
 * Mapper from certificate model to X509Certificate object
 * 
 * Performs mapping from 'raw' certificate model to X509Certificate object
 * 
 */


namespace Arctium.Cryptography.ASN1.Standards.X509.Mapping
{
    public class X509CertificateMapper
    {
        SubjectPublicKeyInfoMapper subjectPublicKeyInfoMapper;
        SignatureMapper signatureAlgoIdentifierMapper;

        public X509CertificateMapper()
        {
            subjectPublicKeyInfoMapper = new SubjectPublicKeyInfoMapper();
            signatureAlgoIdentifierMapper = new SignatureMapper();
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

            cert.Signature = signatureAlgoIdentifierMapper.Map(modelObject.TBSCertificate.Signature);
            cert.SubjectPublicKey = subjectPublicKeyInfoMapper.Map(modelObject.TBSCertificate.SubjectPublicKeyInfo);

            return cert;
        }

        private CertificateExtension[] MapExtensions(ExtensionModel[] extensions)
        {
            List<CertificateExtension> mappedExtensions = new List<CertificateExtension>();
            foreach (var model in extensions)
            {
                var mapped = (new ExtensionsDecoder()).MapModelToExtension(model);
                mappedExtensions.Add(mapped);
            }

            return mappedExtensions.ToArray();
        }
    }
}
