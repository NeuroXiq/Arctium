//using System;
//using Arctium.Cryptography.ASN1.ObjectSyntax.Types;
//using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
//using Arctium.Cryptography.ASN1.Serialization.X690;
//using Arctium.Cryptography.ASN1.Serialization.X690.DER;
//using Arctium.Cryptography.ASN1.Standards.X500.Decoders;
//using Arctium.Cryptography.ASN1.Standards.X500.Types;
//using Arctium.Cryptography.ASN1.Standards.X509.Exceptions;
//using Arctium.Cryptography.ASN1.Standards.X509.Model;
//using X500D = Arctium.Cryptography.ASN1.Standards.X500.Decoders;
//using Arctium.Shared.Helpers.Buffers;



//namespace Arctium.Cryptography.ASN1.Standards.X509.Mapping
//{
//    public class X509CertificateModelMapper
//    {
//        byte[] data;
//        X500D.NameDecoder nameDecoder;

//        public X509CertificateModelMapper(byte[] data)
//        {
//            this.data = data;
//            nameDecoder = new X500D.NameDecoder();
//        }

//        public X509CertificateModel Map(X690DecodedNode decodedNode)
//        {
//            X690DecodedNode rootSequence = decodedNode[0];

//            TBSCertificate tbsCert = MapTbsCertificate(rootSequence[0]);
//            AlgorithmIdentifierModel algorithmIdentifierModel = MapToAlgorithmIdentifierModel(rootSequence[1]);
//            BitString signValue = MapSignatureValue(rootSequence[2]);


//            X509CertificateModel model = new X509CertificateModel(tbsCert, null, signValue);

//            return model;
//        }

//        private AlgorithmIdentifierModel MapToAlgorithmIdentifierModel(X690DecodedNode x690DecodedNode)
//        {
//            throw new NotImplementedException();
//        }

        

        
//    }
//}