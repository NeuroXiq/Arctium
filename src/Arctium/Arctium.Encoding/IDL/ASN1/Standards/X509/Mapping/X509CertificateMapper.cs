using System;
using System.Collections.Generic;
using Arctium.Encoding.IDL.ASN1.Standards.X501.Mapping;
using Arctium.Encoding.IDL.ASN1.Standards.X501.Types;
using Arctium.Encoding.IDL.ASN1.Standards.X509.Mapping;
using Arctium.Encoding.IDL.ASN1.Standards.X509.Model;

/*
 * Mapper from certificate model to X509Certificate object
 * 
 * Performs mapping from 'raw' certificate model to X509Certificate object
 * 
 */


namespace Arctium.Encoding.IDL.ASN1.Standards.X509.X509Certificate.Mapping
{
    public class X509CertificateMapper
    {
        X509ExtensionMapper extensionMapper;
        AlgorithmMapper algorithmIdentifierMapper;
        AttributeTypeMapper attributeTypeMapper;

        public X509CertificateMapper()
        {
            extensionMapper = new X509ExtensionMapper();
            algorithmIdentifierMapper = new AlgorithmMapper();
            attributeTypeMapper = new AttributeTypeMapper();
        }

        public X509Certificate MapFromModel(X509CertificateModel modelObject)
        {
            X509Certificate cert = new X509Certificate();

            cert.Version = (int)modelObject.TBSCertificate.Version.TypedValue.TypedValue.ToULong();
            cert.SerialNumber = modelObject.TBSCertificate.SerialNumber.TypedValue.BinaryValue;

            cert.PublicKeyAlgorithm = algorithmIdentifierMapper.GetPublicKeyAlgorithm(modelObject.TBSCertificate.SubjectPublicKeyInfo.Algorithm.Algorithm.TypedValue);
            cert.SignatureAlgorithm = algorithmIdentifierMapper.GetSignatureAlgorithm(modelObject.TBSCertificate.Signature.Algorithm.TypedValue);
            cert.SignatureValue = modelObject.SignatureValue.TypedValue.Value;
            cert.Issuer = MapNames(modelObject.TBSCertificate.Issuer);
            cert.ValidNotBefore = modelObject.TBSCertificate.Validity.NotBefore;
            cert.ValidNotAfter = modelObject.TBSCertificate.Validity.NotAfter;
            cert.Subject = MapNames(modelObject.TBSCertificate.Subject);
            cert.PublicKey = modelObject.TBSCertificate.SubjectPublicKeyInfo.SubjectPublicKey.TypedValue.Value;
            cert.IssuerUniqueId = modelObject.TBSCertificate.IssuerUniqueId;
            cert.SubjectUniqueId = modelObject.TBSCertificate.SubjectUniqueId;
            cert.Extensions = extensionMapper.Map(modelObject.TBSCertificate.Extensions);

            return cert;
        }

        private TypeNameAttribute[] MapNames(AttributeTypeAndValue[] names)
        {
            List<TypeNameAttribute> mapped = new List<TypeNameAttribute>();

            foreach (var name in names)
            {
                string value = name.Value.Value.ToString();
                string type;

                // if not present because not implemented in mapping, just show OID
                var nameOid = name.Type.TypedValue;

                if (attributeTypeMapper.Contains(nameOid))
                    type = attributeTypeMapper[nameOid];
                else type = nameOid.ToString();

                TypeNameAttribute mappedName = new TypeNameAttribute(type, value);

                mapped.Add(mappedName);
            }

            return mapped.ToArray();
        }
    }
}
