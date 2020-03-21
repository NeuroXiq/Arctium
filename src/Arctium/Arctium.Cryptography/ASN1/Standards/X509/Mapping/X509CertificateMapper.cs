using System;
using System.Collections.Generic;
using Arctium.Cryptography.ASN1.Standards.X500.Mapping.Oid;
using Arctium.Cryptography.ASN1.Standards.X509.Model;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;

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
        PublicKeyMapper publicKeyMap;

        public X509CertificateMapper()
        {
            publicKeyMap = new PublicKeyMapper();
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
            //cert.PublicKeyAlgorithmParams = MapAlgorithmIdParams(modelObject.TBSCertificate.SubjectPublicKeyInfo.Algorithm);
            //cert.SignatureAlgorithmParams = MapAlgorithmIdParams(modelObject.SignatureAlgorithm);
            //cert.PublicKey = publicKeyMap.Map(modelObject.TBSCertificate.SubjectPublicKeyInfo.Algorithm.Algorithm.TypedValue,
            //    modelObject.TBSCertificate.SubjectPublicKeyInfo.SubjectPublicKey.TypedValue);

            //return cert;

            return null;
        }

        private CertificateExtension[] MapExtensions(ExtensionModel[] extensions)
        {
            List<CertificateExtension> mappedExtensions = new List<CertificateExtension>();
            foreach (var model in extensions)
            {
                var mapped = X509ExtensionMapper.MapModelToExtension(model);
                mappedExtensions.Add(mapped);
            }

            return mappedExtensions.ToArray();
        }
    }
}
