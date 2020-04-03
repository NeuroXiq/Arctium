## X509 Certificate V3
This document presents **supported** data structure presented in  
the current implementation of X509 Certificate V3 in Arctium project.
Current status of this implementation is: **Partial-unsafe**	


### Deserialization

```cs
using Arctium.Cryptography.ASN1.Standards.X501.Types;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions;
using Arctium.Cryptography.FileFormat.PEM;
using System;
using System.IO;

namespace DEBUG_ConsoleApplicationForTests
{
    class Program
    {

        static void Main(string[] args)
        {
            // certificate deserializer
            X509CertificateDeserializer deserializer = new X509CertificateDeserializer();

            // Certificate can be decoded in following manner:

            // From Raw Bytes
            byte[] certificateBytes = File.ReadAllBytes("C:\\some_certificate.cer");
            X509Certificate certificateFromRawBytes = deserializer.FromBytes(certificateBytes);

            // From PEM file

            X509Certificate certificateFromPem = deserializer.FromPem("C:\\some_pem.crt");
            
            // Or first decode pem and the raw bytes

            PemFile pemFile = PemFile.FromFile("D:\\some_pem.crt");
            byte[] decodedPemBytes = pemFile.DecodedData;

            //X509Certificate certificateFromPemToBytes = deserializer.FromBytes(decodedPemBytes);


            // Now object is created, examples usage:
            var cert = certificateFromRawBytes;

            Console.WriteLine(cert.ValidNotAfter);
            Console.WriteLine(cert.ValidNotBefore);
            Console.WriteLine(cert.Version);

            RelativeDistinguishedName[] relativeDistinguishedNames = cert.Subject.GetAsRelativeDistinguishedNames();
            Console.WriteLine("Relative distinguished names:");
            foreach (var rdn in relativeDistinguishedNames)
            {
                foreach (var atv in rdn.AttributeTypeAndValues)
                {
                    AttributeType attributeType = atv.Type;
                    string attributeValue = atv.StringValue();
                    Console.WriteLine(" " + attributeType.ToString() + "=" + attributeValue);
                }
            }

            Console.WriteLine("======== extensions =========");

            CertificateExtension[] extensions = cert.Extensions;
            foreach (var ext in extensions)
            {
                Console.WriteLine("Extensions type: " + ext.ExtensionType.ToString());
                switch (ext.ExtensionType)
                {
                    case ExtensionType.SubjectAltName:
                        SubjectAlternativeNamesExtension altName = (SubjectAlternativeNamesExtension)ext;
                        GeneralName[] generalNames = altName.GeneralNames;
                        Console.WriteLine("General names:");
                        foreach (var gn in generalNames)
                        {
                            Console.WriteLine("  " + gn.ToString());
                        }
                        break;
                    case ExtensionType.Unknown:
                        break;
                    case ExtensionType.ExtendedKeyUsage:
                        break;
                    case ExtensionType.KeyUsage:
                        break;
                    case ExtensionType.SubjectKeyIdentifier:
                        break;
                    // and others ....
                }
            }

        }
    }
}

```

Example output:

```
2020-08-05 11:36:04
2019-05-28 14:30:02
2
Relative distinguished names:
 Country=GB
 StateOrProvinceName=London
 Locality=London
 Organization=British Broadcasting Corporation
 CommonName=www.bbc.com
======== extensions =========
Extensions type: KeyUsage
Extensions type: AuthorityInfoAccess
Extensions type: CertificatePolicy
Extensions type: BasicConstraints
Extensions type: CRLDistributionPoints
Extensions type: SubjectAltName
General names:
  www.bbc.com
  fig.bbc.co.uk
  bbc.co.uk
  www.bbc.co.uk
  bbc.com
Extensions type: ExtendedKeyUsage
Extensions type: AuthorityKeyIdentifier
Extensions type: SubjectKeyIdentifier
Extensions type: SCTL
```





### X509Certificate structure

|Certificate field|Type|
|:----:|:----:|
|Version|int||  
|SerialNumber|byte[]||  
|RawSignatureValue|byte[]||  
|Issuer|X500T.Name||  
|ValidNotBefore|DateTime||  
|ValidNotAfter|DateTime||  
|Subject|X500T.Name||  
|IssuerUniqueId|byte[]||  
|SubjectUniqueId|byte[]||  
|Extensions|CertificateExtension[]||  
|Signature|Signature||  
|SubjectPublicKey|SubjectPublicKeyInfo||  


#### Subject Public Key info

|Fields|Type|
|:----:|:-----:|
|AlgorithmType|PublicKeyAlgorithm (enum)|

|Methods|Comment|
|:----:|:---:|
|GetParms<T>|Returns parameters for pulic key (if exists)|
|GetPublicKey<T>|Returns typed public key|

GetPublicKey<T> Generic method parameter **must** be used for casting 
of the inner representation of public key value.
For example:

```cs
    if(certificate.SubjectPublicKey.AlgorithmType == PublicKeyAlgorithm.RSAEncryption)
        { 
            RSAPublicKey rsa = certificate.GetPulicKey<RSAPublicKey>();
            byte[] mod = rsa.Modulus;
            byte[] publicExp = rsa.PulicExponent;
        }
```

Supported casts are present below: 
|AlgorithmType Value|<T> param of GetPublicKey<T>|
|:----:|:---:|
|RSAEncryption|RSAPulicKey|
|ECPublicKey|byte[]|


GetParms<T>
for example:

```cs
if(cert.SubjectPublicKey.ECPublicKey)
{
    EcpkParameters ecParams = cert.GetParms<EcpkParameters>();
    switch(ecParms.ParmsType)
    {
        case EcpkParmsType.ImplicitlyCA:
                // this values is null
            break;
        case EcpkParmsType.ECParameters:
            ECParameters ecTyped = ecParams.GetParams<ECParameters>();
            break;
        case EcpkParmsType.NamedCurve:
            ObjectIdentifier oid = ecParams.GetParams<ObjectIdentifier>();
            break;
    }
}
```

Casting for parameters:
|Type   | Params |
|:-----:|:------:|
|ECPublicKey|EcpkParameters|

### Extensions

All extensions not mentioned in table below are mapped to the  
special type type of extension: **UnknownExtension**  

|Name |Status |Comment|
|:--------:|:--------:|:-----:|
|Authority Info Access|Partial-unsafe|General names problems|
|Certifiate Policies| **OK** | |
|Distribution Points|Partial-unsafe|General names problems|
|Extended Key Usage|**OK**||
|Authority Key Identifier|**OK**||
|Basic Constraints Extension|**OK**||
|Key Usage Extension|**OK**||
|SCTL (Signed certificate timestamp list)|Partial-safe|Class exists (but holds raw data)|
|Subject Alternative Name Extension|Partial-unsafe|General names problems|
|Subject Key Identifier|**OK**||
|Unknown Extension|**OK**|Special Extensions type, if extensions is not on this list, raw ExtValue bytes are present in this object|

