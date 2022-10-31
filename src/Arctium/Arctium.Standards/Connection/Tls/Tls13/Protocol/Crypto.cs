using Arctium.Standards.Connection.Tls.Tls13.Model;
using Arctium.Standards.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Cryptography.Ciphers.BlockCiphers;
using Arctium.Cryptography.Ciphers.BlockCiphers.ModeOfOperation;
using Arctium.Cryptography.Ciphers.DiffieHellman;
using Arctium.Cryptography.Ciphers.EllipticCurves;
using Arctium.Cryptography.Ciphers.EllipticCurves.Algorithms;
using Arctium.Cryptography.Ciphers.StreamCiphers;
using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Cryptography.HashFunctions.KDF;
using Arctium.Cryptography.HashFunctions.MAC;
using Arctium.Cryptography.Utils;
using Arctium.Shared;
using Arctium.Shared.Exceptions;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Other;
using Arctium.Standards;
using Arctium.Standards.RFC;
using Arctium.Standards.DiffieHellman;
using Arctium.Standards.EllipticCurves;
using Arctium.Standards.EllipticCurves.SEC2;
using Arctium.Standards.PKCS1.v2_2;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Arctium.Standards.X509.X509Cert;
using static Arctium.Standards.Connection.Tls.Tls13.Model.Extensions.SignatureSchemeListExtension;
using Arctium.Standards.X509.X509Cert.Algorithms;
using System.Numerics;

namespace Arctium.Standards.Connection.Tls.Tls13.Protocol
{
    internal class Crypto
    {
        public enum RecordLayerKeyType
        {
            Zero_RTT_Application,
            Handshake,
            ApplicationData
        }

        public class SignatureSchemeInfo
        {
            public SignatureScheme SignatureScheme;
            public PublicKeyAlgorithmIdentifierType RelatedPublicKeyType;
            public HashFunctionId SignatureHashFunctionId;
            public SEC2_EllipticCurves.Parameters? SEC2_NamedCurve;
            public NamedCurve? X509Curve;
            public SignatureAlgorithmType X509SignatureAlgorithmType;

            public SignatureSchemeInfo(SignatureScheme scheme,
                PublicKeyAlgorithmIdentifierType relatedWithKeyType,
                HashFunctionId signatureHashFunction,
                SEC2_EllipticCurves.Parameters? sec2NamedCurve = null,
                NamedCurve? x509Curve = null)
            {
                SignatureScheme = scheme;
                RelatedPublicKeyType = relatedWithKeyType;
                SignatureHashFunctionId = signatureHashFunction;
                SEC2_NamedCurve = sec2NamedCurve;
                X509Curve = x509Curve;
            }
        }

        public static readonly SignatureSchemeInfo[] SignaturesInfo = new SignatureSchemeInfo[]
        {
            new SignatureSchemeInfo(SignatureScheme.EcdsaSecp256r1Sha256, PublicKeyAlgorithmIdentifierType.ECPublicKey, HashFunctionId.SHA2_256, SEC2_EllipticCurves.Parameters.secp256r1, NamedCurve.secp256r1),
            new SignatureSchemeInfo(SignatureScheme.EcdsaSecp384r1Sha384, PublicKeyAlgorithmIdentifierType.ECPublicKey, HashFunctionId.SHA2_384, SEC2_EllipticCurves.Parameters.secp384r1, NamedCurve.secp384r1),
            new SignatureSchemeInfo(SignatureScheme.EcdsaSecp521r1Sha512, PublicKeyAlgorithmIdentifierType.ECPublicKey, HashFunctionId.SHA2_512, SEC2_EllipticCurves.Parameters.secp521r1, NamedCurve.secp521r1),
            new SignatureSchemeInfo(SignatureScheme.RsaPssRsaeSha256,     PublicKeyAlgorithmIdentifierType.RSAEncryption, HashFunctionId.SHA2_256),
            new SignatureSchemeInfo(SignatureScheme.RsaPssRsaeSha384,     PublicKeyAlgorithmIdentifierType.RSAEncryption, HashFunctionId.SHA2_384),
            new SignatureSchemeInfo(SignatureScheme.RsaPssRsaeSha512,     PublicKeyAlgorithmIdentifierType.RSAEncryption, HashFunctionId.SHA2_512),
        };

        /// <summary>
        /// Tries to convert certificate signature into TLS 'SignatureScheme' value.
        /// If not possible (for exaple MD5 / DSA etc.) returns null
        /// </summary>
        static SignatureScheme? TryConvertX509SeignatureToTlsSignatureScheme(X509Certificate cert)
        {
            // not simple to implement, need to know signing certificate (parent certificate)
            // to determine for example curvetype SECP512 ... etc.
            throw new NotImplementedException(); //
            

            if (X509Util.IsCertSignatureECDSA(cert))
            {
                // var parameters = var certSignature = cert.SignatureAlgorithm.SignatureAlgorithmParameters
                // if (cert.
            }
            else if (X509Util.IsCerSignatureRSAEncryption(cert))
            {
                
            }

            return null;
        }

        // static readonly Dictionary<SignatureAlgorithmType, SignatureScheme> X509CertSignAlgoToTlsSignAlgo = new Dictionary<SignatureAlgorithmType, SignatureScheme>()
        // {
        //     { SignatureAlgorithmType.SHA384WithRSAEncryption, SignatureScheme.RsaPssRsaeSha384},
        //     { SignatureAlgorithmType.SHA512WithRSAEncryption, SignatureScheme.RsaPssRsaeSha512},
        //     { SignatureAlgorithmType.SHA256WithRSAEncryption, SignatureScheme.RsaPssRsaeSha256},
        //     { SignatureAlgorithmType.ECDSAWithSHA384, SignatureScheme.},
        //     { SignatureAlgorithmType.ECDSAWithSHA256, SignatureScheme.},
        //     { SignatureAlgorithmType.ECDSAWithSHA512, SignatureScheme.},
        // };

        const string ClientCertificateVerifyContextString = "TLS 1.3, client CertificateVerify";

        public readonly IReadOnlyList<CipherSuite> SupportedCipherSuites = new List<CipherSuite>
        {
            CipherSuite.TLS_AES_128_GCM_SHA256
        };

        public byte[] BinderKey;
        public byte[] ClientEarlyTrafficSecret;
        public byte[] EarlyExporterMasterSecret;
        public byte[] ClientHandshakeTrafficSecret;
        public byte[] ServerHandshakeTrafficSecret;
        public byte[] ClientApplicationTrafficSecret0;
        public byte[] ServerApplicationTrafficSecret0;
        public byte[] ExporterMasterSecret;
        public byte[] ResumptionMasterSecret;
        public byte[] EarlySecret;
        public byte[] HandshakeSecret;
        public byte[] MasterSecret;

        public SupportedGroupExtension.NamedGroup SelectedNamedGroup
        {
            get { return selectedNamedGroup.HasValue ? selectedNamedGroup.Value : throw new ArctiumExceptionInternal(); }
            private set { selectedNamedGroup = value; }
        }
        public CipherSuite SelectedCipherSuite
        {
            get { return selectedCipherSuite.HasValue ? selectedCipherSuite.Value : throw new ArctiumExceptionInternal(); }
            private set { selectedCipherSuite = value; }
        }
        public SignatureSchemeListExtension.SignatureScheme SelectedSignatureScheme
        {
            get { return selectedSignatureScheme.HasValue ? selectedSignatureScheme.Value : throw new ArctiumExceptionInternal(); }
            private set { selectedSignatureScheme = value; }
        }
        public HashFunctionId SelectedCipherSuiteHashFunctionId
        {
            get { return selectedCipherSuiteHashFunctionId.HasValue ? selectedCipherSuiteHashFunctionId.Value : throw new ArctiumExceptionInternal(); }
        }

        private static readonly byte[] Tls13Label = Encoding.ASCII.GetBytes("tls13 ");

        HashFunction hashFunction;
        HKDF hkdf;
        HMAC hmac;

        byte[] psk;
        public byte[] Ecdhe_or_dhe_SharedSecret;
        private CipherSuite suite;
        private Endpoint currentEndpoint;

        private SupportedGroupExtension.NamedGroup? selectedNamedGroup = null;
        private CipherSuite? selectedCipherSuite = null;
        private SignatureSchemeListExtension.SignatureScheme? selectedSignatureScheme = null;
        private HashFunctionId? selectedCipherSuiteHashFunctionId = null;

        private API.Tls13ServerConfig config;

        public Crypto(Endpoint currentEndpoint, API.Tls13ServerConfig config)
        {
            this.config = config;
            this.currentEndpoint = currentEndpoint;
            // SetupCryptoAlgorithms(suite, psk, ecdhe_or_dhe);
        }

        public void SetupCryptoAlgorithms(CipherSuite suite)
        {
            this.suite = suite;
            this.selectedCipherSuite = suite;

            HashFunction hkdfHashFunc = null;

            switch (suite)
            {
                case CipherSuite.TLS_AES_128_CCM_SHA256:
                case CipherSuite.TLS_AES_128_GCM_SHA256:
                case CipherSuite.TLS_AES_128_CCM_8_SHA256:
                case CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
                    hashFunction = new SHA2_256();
                    hkdfHashFunc = new SHA2_256();
                    hmac = new HMAC(new SHA2_256(), new byte[0], 0, 0);
                    selectedCipherSuiteHashFunctionId = HashFunctionId.SHA2_256;
                    break;
                case CipherSuite.TLS_AES_256_GCM_SHA384:
                    hashFunction = new SHA2_384();
                    hkdfHashFunc = new SHA2_384();
                    hmac = new HMAC(new SHA2_384(), new byte[0], 0, 0);
                    selectedCipherSuiteHashFunctionId = HashFunctionId.SHA2_384;
                    break;
                default: throw new InvalidOperationException();
            }

            hkdf = new HKDF(new Cryptography.HashFunctions.MAC.HMAC(hkdfHashFunc, new byte[0], 0, 0));
            selectedCipherSuite = suite;
        }

        internal bool VerifyClientFinished(byte[] finishedVerifyDataFromClient, BytesRange handshakeContext)
        {
            // todo verify this
            return true;
        }

        public SignatureScheme? SelectSignatureSchemeForCertificate(X509Certificate certificate, SignatureScheme[] supportedSignatureSchemes)
        {
            var supported = SignaturesInfo.Where(info => supportedSignatureSchemes.Contains(info.SignatureScheme) &&
                info.RelatedPublicKeyType == certificate.SubjectPublicKeyInfo.AlgorithmIdentifier.Algorithm);


            if (supported.Count() == 0) return null;

            if (X509Util.IsCerSignatureRSAEncryption(certificate))
            {
                return supported.First().SignatureScheme;
            }
            else if (X509Util.IsCertSignatureECDSA(certificate))
            {
                var certCurve = certificate.SubjectPublicKeyInfo.AlgorithmIdentifier.Parameters.Choice_EcpkParameters().Choice_NamedCurve();
                var schemeForCurve = supported.Where(s => s.X509Curve == certCurve).ToArray();

                if (schemeForCurve.Length > 0) return schemeForCurve[0].SignatureScheme;
                return null;
            }

            Validation.ThrowInternal();
            return null;
        }

        public byte[] GenerateCertificateVerifySignature(ByteBuffer handshakeContext, X509CertWithKey cert, SignatureScheme signatureScheme, Endpoint endpointGeneratingVerify)
        {
            var info = SignaturesInfo.First(info => info.SignatureScheme == signatureScheme);
            var certPKAlgo = cert.Certificate.SubjectPublicKeyInfo.AlgorithmIdentifier.Algorithm;

            Validation.ThrowInternal(info.RelatedPublicKeyType != cert.Certificate.SubjectPublicKeyInfo.AlgorithmIdentifier.Algorithm);

            // create data to generate signature (from handshake context and format as specification says
            string contextStr = endpointGeneratingVerify == Endpoint.Client ? ClientCertificateVerifyContextString : "TLS 1.3, server CertificateVerify";
            byte[] stringBytes = Encoding.ASCII.GetBytes(contextStr);

            byte[] hash = TranscriptHash(handshakeContext.Buffer, 0, handshakeContext.DataLength);
            byte[] tosign = new byte[64 + stringBytes.Length + 1 + hash.Length];

            int c = 0;

            MemOps.Memset(tosign, 0, 64, 0x20);
            c += 64;
            MemCpy.Copy(stringBytes, 0, tosign, c, stringBytes.Length);
            c += stringBytes.Length;
            tosign[c] = 0;
            c += 1;

            MemCpy.Copy(hash, 0, tosign, c, hash.Length);

            // after formatting data to sign ('tosing' byte array)
            // generate signature for selected 'signatureScheme'
            byte[] resultSignature = null;

            if (certPKAlgo == PublicKeyAlgorithmIdentifierType.RSAEncryption)
            {
                var keyFromCert = cert.PrivateKey.Choice_RSAPrivateKeyCRT();
                var keyForPkcs1 = new PKCS1v2_2API.PrivateKey(keyFromCert);

                resultSignature = PKCS1v2_2API.RSASSA_PSS_SIGN(keyForPkcs1, tosign, info.SignatureHashFunctionId);
            }
            else if (certPKAlgo == PublicKeyAlgorithmIdentifierType.ECPublicKey)
            {
                var certPrivKey = cert.PrivateKey.Choice_ECPrivateKey().PrivateKey;

                var ecparams = SEC2_EllipticCurves.CreateParameters(info.SEC2_NamedCurve.Value);
                var ecsignature = SEC1_Fp.ECDSA_SigningOperation(ecparams, info.SignatureHashFunctionId, tosign, certPrivKey);

                var ecdsasigval = new EcdsaSigValue(ecsignature);
                resultSignature = X509Util.ASN1_DerEncodeEcdsaSigValue(ecdsasigval);
            }
            else Validation.ThrowInternal("something is wrong because certificate doesn't match with selected signaturescheme");

            return resultSignature;
        }

        byte[] FormatDataForSignature(byte[] handshakeContext, int dataLength, bool forClient)
        {
            string contextStr = forClient ? ClientCertificateVerifyContextString :  "TLS 1.3, server CertificateVerify";
            byte[] stringBytes = Encoding.ASCII.GetBytes(contextStr);
            byte[] hash = TranscriptHash(handshakeContext, 0, dataLength);

            byte[] tosign = new byte[64 + stringBytes.Length + 1 + hash.Length];

            int c = 0;

            MemOps.Memset(tosign, 0, 64, 0x20);
            c += 64;
            MemCpy.Copy(stringBytes, 0, tosign, c, stringBytes.Length);
            c += stringBytes.Length;
            tosign[c] = 0;
            c += 1;

            MemCpy.Copy(hash, 0, tosign, c, hash.Length);

            return tosign;
        }

        public void GeneratePrivateKeyAndKeyShareToSend(SupportedGroupExtension.NamedGroup namedGroup, out byte[] keyShareToSendRawBytes, out byte[] privateKey)
        {
            if (namedGroup == SupportedGroupExtension.NamedGroup.Xx448)
            {
                privateKey = new byte[RFC7748.X448_PrivateKeyLengthBytes];
                GlobalConfig.RandomGeneratorCryptSecure(privateKey, 0, RFC7748.X448_PrivateKeyLengthBytes);

                keyShareToSendRawBytes = RFC7748.X448_UCoord_5(privateKey);
            }
            else if (namedGroup == SupportedGroupExtension.NamedGroup.X25519)
            {
                privateKey = new byte[RFC7748.X25519_PrivateKeyLengthBytes];
                GlobalConfig.RandomGeneratorCryptSecure(privateKey, 0, RFC7748.X25519_PrivateKeyLengthBytes);

                keyShareToSendRawBytes = RFC7748.X25519_UCoord_9(privateKey);
            }
            else if ((new[] { SupportedGroupExtension.NamedGroup.Secp256r1,
                    SupportedGroupExtension.NamedGroup.Secp384r1,
                    SupportedGroupExtension.NamedGroup.Secp521r1 })
                        .Any(x => x == namedGroup))
            {
                SEC2_EllipticCurves.Parameters parms;

                switch (namedGroup)
                {
                    case SupportedGroupExtension.NamedGroup.Secp256r1: parms = SEC2_EllipticCurves.Parameters.secp256r1; break;
                    case SupportedGroupExtension.NamedGroup.Secp384r1: parms = SEC2_EllipticCurves.Parameters.secp384r1; break;
                    case SupportedGroupExtension.NamedGroup.Secp521r1: parms = SEC2_EllipticCurves.Parameters.secp521r1; break;
                    default: throw new NotSupportedException("never happen");
                }

                var ecparams = SEC2_EllipticCurves.CreateParameters(parms);

                ECFpPoint pointToSend;
                var secret = SEC1_ECFpAlgorithm.EllipticCurveKeyPairGenerationPrimitive(ecparams, out pointToSend);

                privateKey = secret;
                keyShareToSendRawBytes = SEC1_Fp.EllipticCurvePointToOctetString(ecparams, pointToSend, SEC1_Fp.ECPointCompression.NotCompressed);
            }
            else if (
                namedGroup == SupportedGroupExtension.NamedGroup.Ffdhe2048 ||
                namedGroup == SupportedGroupExtension.NamedGroup.Ffdhe3072 ||
                namedGroup == SupportedGroupExtension.NamedGroup.Ffdhe4096 ||
                namedGroup == SupportedGroupExtension.NamedGroup.Ffdhe6144 ||
                namedGroup == SupportedGroupExtension.NamedGroup.Ffdhe8192)
            {
                FFDHE_RFC7919.SupportedGroupRegistry group = (FFDHE_RFC7919.SupportedGroupRegistry)namedGroup;

                var ffdheParams = FFDHE_RFC7919.GetFFDHEParams(group);

                FFDHE.GeneratePrivateAndPublicKey(ffdheParams, out privateKey, out keyShareToSendRawBytes);
            }
            else throw new NotSupportedException();
        }

        public void ComputeSharedSecret(SupportedGroupExtension.NamedGroup namedGroup, byte[] privateKey, byte[] keyExchangeRawBytes)
        {
            if (namedGroup == SupportedGroupExtension.NamedGroup.Xx448)
            {
                this.Ecdhe_or_dhe_SharedSecret = RFC7748.X448(privateKey, keyExchangeRawBytes);
            }
            else if (namedGroup == SupportedGroupExtension.NamedGroup.X25519)
            {
                byte[] sharedSecret = RFC7748.X25519(privateKey, keyExchangeRawBytes);

                this.Ecdhe_or_dhe_SharedSecret = sharedSecret;
            }
            else if ((new[] { SupportedGroupExtension.NamedGroup.Secp256r1,
                    SupportedGroupExtension.NamedGroup.Secp384r1,
                    SupportedGroupExtension.NamedGroup.Secp521r1 })
                        .Any(x => x == namedGroup))
            {
                SEC2_EllipticCurves.Parameters parms;

                switch (namedGroup)
                {
                    case SupportedGroupExtension.NamedGroup.Secp256r1: parms = SEC2_EllipticCurves.Parameters.secp256r1; break;
                    case SupportedGroupExtension.NamedGroup.Secp384r1: parms = SEC2_EllipticCurves.Parameters.secp384r1; break;
                    case SupportedGroupExtension.NamedGroup.Secp521r1: parms = SEC2_EllipticCurves.Parameters.secp521r1; break;
                    default: throw new NotSupportedException("never happen");
                }

                var ecparams = SEC2_EllipticCurves.CreateParameters(parms);
                var clientPoint = SEC1_Fp.OctetStringToEllipticCurvePoint(keyExchangeRawBytes, ecparams);

                this.Ecdhe_or_dhe_SharedSecret = SEC1_ECFpAlgorithm.EllipticCurveDiffieHellmanPrimitive(ecparams, privateKey, clientPoint);
            }
            else if (
                namedGroup == SupportedGroupExtension.NamedGroup.Ffdhe2048 ||
                namedGroup == SupportedGroupExtension.NamedGroup.Ffdhe3072 ||
                namedGroup == SupportedGroupExtension.NamedGroup.Ffdhe4096 ||
                namedGroup == SupportedGroupExtension.NamedGroup.Ffdhe6144 ||
                namedGroup == SupportedGroupExtension.NamedGroup.Ffdhe8192)
            {
                FFDHE_RFC7919.SupportedGroupRegistry group = (FFDHE_RFC7919.SupportedGroupRegistry)namedGroup;

                var ffdheParams = FFDHE_RFC7919.GetFFDHEParams(group);

                this.Ecdhe_or_dhe_SharedSecret = FFDHE.ComputeSharedSecret(ffdheParams, privateKey, keyExchangeRawBytes);
            }
            else throw new NotSupportedException();
        }

        //public bool IsClientPostHandshakeCertificateVerifyValid(byte[] hscontext, int hscontextlen, CertificateVerify clientCertificateVerify, X509Certificate clientCertificate)
        //{
        //    return false;
        //}

        public bool IsClientCertificateVerifyValid(byte[] hscontext, int hscontextlen, CertificateVerify clientCertificateVerify, X509Certificate clientCertificate)
        {
            byte[] toSign = FormatDataForSignature(hscontext, hscontextlen, true);
            return IsSignatureValid(toSign, clientCertificateVerify, clientCertificate);
        }

        internal bool IsServerCertificateVerifyValid(byte[] hscontext,
            int hscontextlen,
            CertificateVerify certVerify,
            X509Certificate serverCertificate)
        {
            byte[] toSign = FormatDataForSignature(hscontext, hscontextlen, false);
            return IsSignatureValid(toSign, certVerify, serverCertificate);
        }

        public bool IsSignatureValid(byte[] toSign, CertificateVerify certVerify, X509Certificate certificateThatSignedData)
        {
            HashFunctionId hashFunctionId;
            ECFpDomainParameters ecparams = null;

            switch (certVerify.SignatureScheme)
            {
                case SignatureScheme.RsaPssRsaeSha256:
                case SignatureScheme.EcdsaSecp256r1Sha256:
                    hashFunctionId = HashFunctionId.SHA2_256;
                    ecparams = SEC2_EllipticCurves.CreateParameters(SEC2_EllipticCurves.Parameters.secp256r1);
                    break;
                case SignatureScheme.EcdsaSecp384r1Sha384:
                case SignatureScheme.RsaPssRsaeSha384:
                    hashFunctionId = HashFunctionId.SHA2_384;
                    ecparams = SEC2_EllipticCurves.CreateParameters(SEC2_EllipticCurves.Parameters.secp384r1);
                    break;
                case SignatureScheme.EcdsaSecp521r1Sha512:
                case SignatureScheme.RsaPssRsaeSha512:
                    hashFunctionId = HashFunctionId.SHA2_512;
                    ecparams = SEC2_EllipticCurves.CreateParameters(SEC2_EllipticCurves.Parameters.secp521r1);
                    break;
                    //case SignatureScheme.Ed25519:
                    //    hashFunctionId = HashFunctionId.SHA2_512
                    //    break;
                    //case SignatureScheme.Ed448:
                    break;
                default: throw new NotSupportedException("not supported signatue scheme: " + certVerify.SignatureScheme.ToString());
            }

            switch (certVerify.SignatureScheme)
            {
                case SignatureScheme.EcdsaSecp256r1Sha256:
                    ecparams = SEC2_EllipticCurves.CreateParameters(SEC2_EllipticCurves.Parameters.secp256r1);
                    break;
                case SignatureScheme.EcdsaSecp384r1Sha384:
                    ecparams = SEC2_EllipticCurves.CreateParameters(SEC2_EllipticCurves.Parameters.secp384r1);
                    break;
                case SignatureScheme.EcdsaSecp521r1Sha512:
                    ecparams = SEC2_EllipticCurves.CreateParameters(SEC2_EllipticCurves.Parameters.secp521r1);
                    break;

                default: break;
            }

            var rsaeAlgos = new SignatureScheme[] { SignatureScheme.RsaPssRsaeSha256, SignatureScheme.RsaPssRsaeSha384, SignatureScheme.RsaPssRsaeSha512 };
            var ecdsaAlgos = new SignatureScheme[] { SignatureScheme.EcdsaSecp521r1Sha512, SignatureScheme.EcdsaSecp384r1Sha384, SignatureScheme.EcdsaSecp256r1Sha256 };

            if (rsaeAlgos.Contains(certVerify.SignatureScheme))
            {
                var defPubKey = X509Util.GetRSAPublicKeyDefault(certificateThatSignedData);
                var apiKey = PKCS1v2_2API.PublicKey.FromDefault(defPubKey);

                return PKCS1v2_2API.RSASSA_PSS_VERIFY(apiKey, toSign, certVerify.Signature, hashFunctionId);
            }
            else if (ecdsaAlgos.Contains(certVerify.SignatureScheme))
            {

                var ecpubkey = certificateThatSignedData.SubjectPublicKeyInfo.PublicKey.Get<byte[]>();
                var publicKeyPoint = SEC1_ECFpAlgorithm.OctetStringToEllipticCurvePoint(ecpubkey, ecparams);

                var sigValue = X509Util.ASN1_DerDecodeEcdsaSigValue(certVerify.Signature);

                var ecsignature = new ECSignature(sigValue.R, sigValue.S);

                bool isvalid = SEC1_ECFpAlgorithm.ECDSA_Verify(ecparams, hashFunctionId, toSign, publicKeyPoint, ecsignature);

                return isvalid;
            }
            else throw new NotSupportedException("certverify not supported");
        }

        internal bool VerifyClientCertificate(CertificateVerify certVer)
        {
            //todo implement this
            return true;
        }

        internal int GetHashSizeInBytes(HashFunctionId hashFunctionId)
        {
            switch (hashFunctionId)
            {
                case HashFunctionId.SHA2_256: return 32;
                case HashFunctionId.SHA2_384: return 48;
            }

            Validation.ThrowInternal(); return -1;
        }

        public byte[] GeneratePsk(byte[] resumptionMasterSecretFromPreviousSession, byte[] ticketNonce)
        {
            return HkdfExpandLabel(resumptionMasterSecretFromPreviousSession, "resumption", ticketNonce, hashFunction.HashSizeBytes);
        }

        public void SelectCipherSuite(CipherSuite serverHelloSuite)
        {
            this.SetupCryptoAlgorithms(serverHelloSuite);
        }

        public void SelectCipherSuite(ClientHello hello, out bool cipherSuiteOk)
        {
            var supportedCipherSuites = config.CipherSuites;
            var clientCiphers = hello.CipherSuites;
            int selectedCipherSuiteIdx = -1;

            for (int i = 0; i < supportedCipherSuites.Length && selectedCipherSuiteIdx == -1; i++)
                for (int j = 0; j < clientCiphers.Length && selectedCipherSuiteIdx == -1; j++)
                {
                    if (supportedCipherSuites[i] == clientCiphers[j]) selectedCipherSuiteIdx = i;
                }

            cipherSuiteOk = clientCiphers.Length > 0 && selectedCipherSuiteIdx < supportedCipherSuites.Length && selectedCipherSuiteIdx >= 0;
            if (cipherSuiteOk) this.SetupCryptoAlgorithms(supportedCipherSuites[selectedCipherSuiteIdx]);
        }

        public void SelectEcEcdheGroup(ClientHello hello, out bool groupOk)
        {
            var supportedGroups = config.NamedGroups; // new SupportedGroupExtension.NamedGroup[] { SupportedGroupExtension.NamedGroup.X25519 };
            var clientGroups = hello.GetExtension<SupportedGroupExtension>(ExtensionType.SupportedGroups).NamedGroupList;
            int selectedGroupIdx = -1;

            for (int i = 0; i < supportedGroups.Length && selectedGroupIdx == -1; i++)
                for (int j = 0; j < clientGroups.Length && selectedGroupIdx == -1; j++)
                {
                    if (supportedGroups[i] == clientGroups[j]) selectedGroupIdx = i;
                }

            groupOk = clientGroups.Length > 0 && selectedGroupIdx < supportedGroups.Length && selectedGroupIdx >= 0;
            if (groupOk) this.SelectedNamedGroup = supportedGroups[selectedGroupIdx];
        }

        public bool SelectSigAlgoAndCert(
            SignatureScheme[] clientHelloSignatureSchemes,
            SignatureScheme[] clientHelloCertificateSignatureSchemes,
            X509CertWithKey[] availableCertificates,
            ref SignatureScheme? signature,
            ref X509CertWithKey selectedcert)
        {
            clientHelloCertificateSignatureSchemes = clientHelloCertificateSignatureSchemes ?? new SignatureScheme[0];

            var mutualSignatures = clientHelloSignatureSchemes.Where(clientSig => config.SignatureSchemes.Contains(clientSig));
            var possibleSignatures = SignaturesInfo.Where(info => mutualSignatures.Contains(info.SignatureScheme));

            if (mutualSignatures.Count() == 0) return false;

            var possibleCertificates = config.CertificatesWithKeys.Where(certWithKey =>
            {
                var certpubkey = certWithKey.Certificate.SubjectPublicKeyInfo.AlgorithmIdentifier.Algorithm;

                if (certpubkey == PublicKeyAlgorithmIdentifierType.RSAEncryption)
                    return possibleSignatures.Any(info => info.RelatedPublicKeyType == PublicKeyAlgorithmIdentifierType.RSAEncryption);

                return possibleSignatures.Any(info => info.X509Curve == certWithKey.Certificate.SubjectPublicKeyInfo.AlgorithmIdentifier.Parameters.Choice_EcpkParameters().Choice_NamedCurve());

            });

            if (possibleCertificates.Count() == 0) return false;

            if (possibleCertificates.Count() > 1 &&
                clientHelloCertificateSignatureSchemes != null &&
                clientHelloCertificateSignatureSchemes.Length > 0)
            {
                // todo tls13 clientHelloCertificateSignatureSchemes select certificate if possible
                // for now not implemented
            }

            var firstValidCert = possibleCertificates.First();
            
            selectedcert = firstValidCert;

            signature = possibleSignatures.First(info =>
            {
                var algoid = firstValidCert.Certificate.SubjectPublicKeyInfo.AlgorithmIdentifier;
                if (algoid.Algorithm == PublicKeyAlgorithmIdentifierType.RSAEncryption)
                {
                    return info.RelatedPublicKeyType == PublicKeyAlgorithmIdentifierType.RSAEncryption;
                }
                else
                {
                    return info.X509Curve == algoid.Parameters.Choice_EcpkParameters().Choice_NamedCurve();
                }
            }).SignatureScheme;

            return true;
        }

        public byte[] TranscriptHash(byte[] buffer, long offset, long length)
        {
            hashFunction.Reset();

            hashFunction.HashBytes(buffer, 0, length);

            return hashFunction.HashFinal();
        }

        public byte[] TranscriptHash(params byte[][] m)
        {
            hashFunction.Reset();

            foreach (byte[] buf in m)
            {
                hashFunction.HashBytes(buf);
            }

            return hashFunction.HashFinal();
        }

        public byte[] TranscriptHash(ByteBuffer buf)
        {
            hashFunction.Reset();

            hashFunction.HashBytes(buf.Buffer, 0, buf.DataLength);

            return hashFunction.HashFinal();
        }

        public void ChangeRecordLayerCrypto(RecordLayer recordLayer, RecordLayerKeyType keyType)
        {
            byte[] clientSecret;
            byte[] serverSecret;

            switch (keyType)
            {
                case RecordLayerKeyType.Zero_RTT_Application: throw new NotImplementedException();
                case RecordLayerKeyType.Handshake:
                    clientSecret = ClientHandshakeTrafficSecret;
                    serverSecret = ServerHandshakeTrafficSecret;
                    break;
                case RecordLayerKeyType.ApplicationData:
                    clientSecret = ClientApplicationTrafficSecret0;
                    serverSecret = ServerApplicationTrafficSecret0;
                    break;
                default: throw new ArgumentException(nameof(keyType));
            }

            byte[] clientWriteIv, serverWriteIv, ckey, skey;
            AEAD serverWriteAead, clientWriteAead;

            switch (SelectedCipherSuite)
            {
                case CipherSuite.TLS_AES_128_GCM_SHA256:
                    ckey = HkdfExpandLabel(clientSecret, "key", new byte[0], 16);
                    skey = HkdfExpandLabel(serverSecret, "key", new byte[0], 16);
                    clientWriteIv = HkdfExpandLabel(clientSecret, "iv", new byte[0], 12);
                    serverWriteIv = HkdfExpandLabel(serverSecret, "iv", new byte[0], 12);

                    serverWriteAead = new GaloisCounterMode(new AES(skey), 16);
                    clientWriteAead = new GaloisCounterMode(new AES(ckey), 16);
                    break;
                case CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
                    ckey = HkdfExpandLabel(clientSecret, "key", new byte[0], 32);
                    skey = HkdfExpandLabel(serverSecret, "key", new byte[0], 32);
                    clientWriteIv = HkdfExpandLabel(clientSecret, "iv", new byte[0], 12);
                    serverWriteIv = HkdfExpandLabel(serverSecret, "iv", new byte[0], 12);

                    serverWriteAead = new AEAD_CHACHA20_POLY1305(skey);
                    clientWriteAead = new AEAD_CHACHA20_POLY1305(ckey);
                    break;
                case CipherSuite.TLS_AES_128_CCM_SHA256:
                    ckey = HkdfExpandLabel(clientSecret, "key", new byte[0], 16);
                    skey = HkdfExpandLabel(serverSecret, "key", new byte[0], 16);
                    clientWriteIv = HkdfExpandLabel(clientSecret, "iv", new byte[0], 12);
                    serverWriteIv = HkdfExpandLabel(serverSecret, "iv", new byte[0], 12);

                    serverWriteAead = RFC5116_AEAD_Predefined.Create_AEAD_AES_128_CCM(skey);
                    clientWriteAead = RFC5116_AEAD_Predefined.Create_AEAD_AES_128_CCM(ckey);
                    break;
                case CipherSuite.TLS_AES_256_GCM_SHA384:
                    ckey = HkdfExpandLabel(clientSecret, "key", new byte[0], 32);
                    skey = HkdfExpandLabel(serverSecret, "key", new byte[0], 32);
                    clientWriteIv = HkdfExpandLabel(clientSecret, "iv", new byte[0], 12);
                    serverWriteIv = HkdfExpandLabel(serverSecret, "iv", new byte[0], 12);

                    serverWriteAead = RFC5116_AEAD_Predefined.Create_AEAD_AES_256_GCM(skey);
                    clientWriteAead = RFC5116_AEAD_Predefined.Create_AEAD_AES_256_GCM(ckey);
                    break;
                default: throw new NotImplementedException();
            }

            if (currentEndpoint == Endpoint.Client)
            {
                recordLayer.ChangeCipher(clientWriteAead, serverWriteAead, clientWriteIv, serverWriteIv);
            }
            else
            {
                recordLayer.ChangeCipher(serverWriteAead, clientWriteAead, serverWriteIv, clientWriteIv);
            }
        }

        #region Secrets generation

        public void SetupEarlySecret(byte[] psk)
        {
            byte[] zeroValueOfHashLen = new byte[hashFunction.HashSizeBytes];
            this.psk = psk;
            byte[] pskSecret = this.psk != null ? psk : zeroValueOfHashLen;
            EarlySecret = new byte[this.hashFunction.HashSizeBytes];

            bool externalBinder = false; // todo?

            hkdf.Extract(zeroValueOfHashLen, pskSecret, EarlySecret);
        }

        public void SetupHandshakeSecret(ByteBuffer hscontext)
        {
            byte[] derived = DeriveSecret(EarlySecret, "derived", new byte[0]);

            HandshakeSecret = new byte[hashFunction.HashSizeBytes];
            hkdf.Extract(derived, this.Ecdhe_or_dhe_SharedSecret, HandshakeSecret);
            
            ClientHandshakeTrafficSecret = DeriveSecret(HandshakeSecret, "c hs traffic", hscontext);
            ServerHandshakeTrafficSecret = DeriveSecret(HandshakeSecret, "s hs traffic", hscontext);
        }

        public void SetupMasterSecret(ByteBuffer hscontext)
        {
            byte[] derived = DeriveSecret(HandshakeSecret, "derived", new byte[0]);
            byte[] zeroValueOfHashLen = new byte[hashFunction.HashSizeBytes];
            MasterSecret = new byte[this.hashFunction.HashSizeBytes];

            hkdf.Extract(derived, zeroValueOfHashLen, MasterSecret);

            ClientApplicationTrafficSecret0 = DeriveSecret(MasterSecret, "c ap traffic", hscontext);
            ServerApplicationTrafficSecret0 = DeriveSecret(MasterSecret, "s ap traffic", hscontext);
            ExporterMasterSecret = DeriveSecret(MasterSecret, "exp master", hscontext);
        }

        public void SetupResumptionMasterSecret(ByteBuffer hsctx)
        {
            ResumptionMasterSecret = DeriveSecret(MasterSecret, "res master", hsctx);
        }

        #endregion

        public byte[] ComputeFinishedVerData(ByteBuffer handshakeContext, Endpoint endpoint, bool isPostHandshake = false)
        {
            // byte[] baseKey = endpoint == Endpoint.Server ? ServerHandshakeTrafficSecret : ClientHandshakeTrafficSecret;

            byte[] baseKey = null;

            if (endpoint == Endpoint.Client && !isPostHandshake) baseKey = ClientHandshakeTrafficSecret;
            else if (endpoint == Endpoint.Client && isPostHandshake) baseKey = ClientApplicationTrafficSecret0;
            else if (endpoint == Endpoint.Server && !isPostHandshake) baseKey = ServerHandshakeTrafficSecret;
            else if (endpoint == Endpoint.Server && isPostHandshake) baseKey = ServerApplicationTrafficSecret0;
            else Validation.ThrowInternal();


            byte[] finishedKey = HkdfExpandLabel(baseKey, "finished", new byte[0], hashFunction.HashSizeBytes);
            byte[] result = new byte[hmac.HashFunctionHashSizeBytes];

            hmac.Reset();
            
            hmac.ChangeKey(finishedKey);
            var transcriptHash = TranscriptHash(handshakeContext);
            hmac.ProcessBytes(transcriptHash);

            hmac.Final(result, 0);

            return result;
        }

        public bool IsPskBinderValueValid(ByteBuffer handshakeContextToBinders,
            int lengthToPskBindersInBuffer,
            byte[] clientBinderValue)
        {
            if (psk == null) throw new ArctiumExceptionInternal("psk must be set");
            var baseKey = GenerateBinderKey(psk, this.hkdf, this.hashFunction);

            // var hash = HandshakeContextTranscriptHash(handshakeContext, -1, true);
            var hash = TranscriptHash(handshakeContextToBinders.Buffer, 0, lengthToPskBindersInBuffer);
            byte[] result = new byte[hash.Length];

            byte[] baseKeyForHash = HkdfExpandLabel(baseKey, "finished", new byte[0], hashFunction.HashSizeBytes);

            hmac.Reset();
            hmac.ChangeKey(baseKeyForHash);
            hmac.ProcessBytes(hash);
            hmac.Final(result, 0);

            return MemOps.Memcmp(result, clientBinderValue);
        }

        byte[] TranscriptHash(HashFunction hf, byte[] msg)
        {
            hf.Reset();

            hf.HashBytes(msg);
            var r = hf.HashFinal();

            hf.Reset();

            return r;
        }

        public byte[] GenerateBinderKey(byte[] psk, HKDF hkdf, HashFunction hf)
        {
            var hashSizeBytes = hf.HashSizeBytes;
            byte[] zeroValueOfHashLen = new byte[hashSizeBytes];
            this.psk = psk;
            byte[] pskSecret = this.psk != null ? psk : zeroValueOfHashLen;
            var earlySecret = new byte[hashSizeBytes];

            bool externalBinder = false; // ? 

            hkdf.Extract(zeroValueOfHashLen, pskSecret, earlySecret);

            var binderKey = HkdfExpandLabel(hkdf, earlySecret, externalBinder ? "ext binder" : "res binder", TranscriptHash(hf, new byte[0]), hashSizeBytes);

            return binderKey;
        }

        public byte[] ComputeBinderValue(ByteBuffer hscontextToBinders, API.PskTicket ticket)
        {
            // byte[] psk = GeneratePsk(ticket.ResumptionMasterSecret, ticket.TicketNonce);
            
            var hashFunc = CryptoAlgoFactory.CreateHashFunction(ticket.HashFunctionId);
            var hkdf = new HKDF(new HMAC(CryptoAlgoFactory.CreateHashFunction(ticket.HashFunctionId), new byte[0], 0, 0));
            var hmac = new HMAC(CryptoAlgoFactory.CreateHashFunction(ticket.HashFunctionId), new byte[0], 0, 0);

            byte[] psk = HkdfExpandLabel(hkdf, ticket.ResumptionMasterSecret, "resumption", ticket.TicketNonce, hashFunc.HashSizeBytes);
            var baseKey = GenerateBinderKey(psk, hkdf, hashFunc);
            var binderKeyForHash = HkdfExpandLabel(hkdf, baseKey, "finished", new byte[0], hashFunc.HashSizeBytes);

            hashFunc.HashBytes(hscontextToBinders.Buffer, 0, hscontextToBinders.DataLength);
            var hash = hashFunc.HashFinal();

            byte[] result = new byte[hashFunc.HashSizeBytes];

            hmac.Reset();
            hmac.ChangeKey(binderKeyForHash);
            hmac.ProcessBytes(hash);
            hmac.Final(result, 0);

            return result;
        }

        public void ReplaceClientHello1WithMessageHash(ByteBuffer hsctx, int CH1Length)
        {
            // remove original client hello
            byte[] clientHello1Hash = TranscriptHash(hsctx.Buffer, 0, CH1Length);
            hsctx.TrimStart(CH1Length);
            hsctx.PrependOutside(4 + clientHello1Hash.Length);
            

            // insert hashed client hello
            hsctx.Buffer[0] = (byte)HandshakeType.MessageHash;
            MemMap.ToBytes1UShortBE((ushort)clientHello1Hash.Length, hsctx.Buffer, 2);
            MemCpy.Copy(clientHello1Hash, 0, hsctx.Buffer, 4, clientHello1Hash.Length);
        }

        public void ClientFinished()
        {
            throw new NotImplementedException();
        }

        public void PostHandshakeFinished()
        {
            throw new Exception();
        }

        byte[] HkdfExpandLabel(HKDF hkdf, byte[] secret, string labelText, byte[] context, int length)
        {
            byte[] label = Encoding.ASCII.GetBytes(labelText);
            byte[] result = new byte[length];
            byte labelLen = (byte)(label.Length + Tls13Label.Length);

            byte[] hkdfLabel = new byte[2 + 1 + 1 + context.Length + Tls13Label.Length + label.Length];
            MemMap.ToBytes1UShortBE((ushort)length, hkdfLabel, 0);
            hkdfLabel[2] = labelLen;

            MemCpy.Copy(Tls13Label, 0, hkdfLabel, 3, Tls13Label.Length);
            MemCpy.Copy(label, 0, hkdfLabel, 3 + Tls13Label.Length, label.Length);

            int contextStart = 2 + 1 + Tls13Label.Length + label.Length;

            hkdfLabel[contextStart] = (byte)context.Length;

            MemCpy.Copy(context, 0, hkdfLabel, contextStart + 1, context.Length);

            hkdf.Expand(secret, hkdfLabel, result, length);

            return result;
        }

        byte[] HkdfExpandLabel(byte[] secret, string labelText, byte[] context, int length)
        {
            return HkdfExpandLabel(this.hkdf, secret, labelText, context, length);
        }

        byte[] DeriveSecret(byte[] secret, string label, byte[] messages)
        {
            return HkdfExpandLabel(secret, label, TranscriptHash(messages), hashFunction.HashSizeBytes);
        }

        byte[] DeriveSecret(byte[] secret, string label, ByteBuffer messages)
        {
            return HkdfExpandLabel(secret, label, TranscriptHash(messages), hashFunction.HashSizeBytes);
        }
    }
}
