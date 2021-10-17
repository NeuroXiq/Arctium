using X500T = Arctium.Standards.X501.Types;

// using Arctium.Cryptography.Shared.Algorithms;
using Arctium.Shared.Algorithms;
using System;
using Arctium.Standards.X509.X509Cert.Extensions;


/*
 * - Class info -
 * 
 * X509 Certificate defined as an object 
 * 
 * Holds all certificate data ready-to-work defined in x509 rfc specification
 * 
 *  This class is a final element which shall be used as an end 'entity'.
 * Contains most commond fields and methods typically used in work with certificates.
 *  This is a 'convenient' equivalent of X509CertificateModel class without all 
 * raw ASN.1 object artifacts, with valid encapsulation etc.
 *  Note 1: Consider that in comparison to 'Model' class, this class cannot be 
 * easy converted to ASN.1 object nor to der encoded raw bytes. Only purpose is to have
 * some convenient place to work with certificate
 *  Note 2: All references present in 'Model' class are just copied to this class + parsed extensions
 * 
 */


namespace Arctium.Standards.X509.X509Cert
{
    /// <summary>
    /// Represents a X509Certifiate.
    /// </summary>
    public class X509Certificate
    {
        public int Version { get; internal set; }
        public byte[] SerialNumber { get; internal set; }
        public X500T.Name Issuer { get; internal set; }
        public DateTime ValidNotBefore { get; internal set; }
        public DateTime ValidNotAfter { get; internal set; }
        public X500T.Name Subject { get; internal set; }
        public byte[] IssuerUniqueId { get; internal set; }
        public byte[] SubjectUniqueId { get; internal set; }
        public CertificateExtension[] Extensions { get; internal set; }
        public Signature Signature { get; internal set; }
        public SubjectPublicKeyInfo SubjectPublicKey { get; internal set; }
    }
}
