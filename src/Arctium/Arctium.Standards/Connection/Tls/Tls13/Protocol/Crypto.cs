using Arctium.Standards.Connection.Tls.Tls13.API;
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
using Arctium.Standards.Crypto;
using Arctium.Standards.DiffieHellman;
using Arctium.Standards.EllipticCurves;
using Arctium.Standards.EllipticCurves.SEC2;
using Arctium.Standards.PKCS1.v2_2;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Arctium.Standards.Connection.Tls.Tls13.Protocol
{
    internal class Crypto
    {
        public enum KeyScheduleKey
        {

        }

        public enum RecordLayerKeyType
        {
            Zero_RTT_Application,
            Handshake,
            ApplicationData
        }

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

        private Tls13ServerConfig config;

        public Crypto(Endpoint currentEndpoint, Tls13ServerConfig config)
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

        internal bool VerifyClientFinished(byte[] finishedVerifyDataFromClient, ByteBuffer handshakeContext)
        {
            // todo verify this
            return true;
        }

        internal byte[] GenerateServerCertificateVerifySignature(ByteBuffer handshakeContext)
        {
            if (SelectedSignatureScheme != SignatureSchemeListExtension.SignatureScheme.RsaPssRsaeSha256) throw new Exception();
            var hashFuncType = HashFunctionId.SHA2_256;

            // var ext = this.clientHello.GetExtension<SignatureSchemeListExtension>(ExtensionType.SignatureAlgorithms);
            // ext.Schemes.Single(s => s == SignatureSchemeListExtension.SignatureScheme.RsaPssRsaeSha256);

            string contextStr = "TLS 1.3, server CertificateVerify";
            byte[] stringBytes = Encoding.ASCII.GetBytes(contextStr);

            //List<byte[]> tohash = new List<byte[]>();
            // 
            //tohash.Add(MemCpy.CopyToNewArray(handshakeContext.HandshakeMessages, 0, handshakeContext.TotalLength));
            //tohash.AddRange(handshakeContext.Select(x => x.Value));
            // tohash.Add(this.serverConfig.DerEncodedCertificateBytes);

            //byte[] hash = TranscriptHash(tohash.ToArray());
            //byte[] hash = HandshakeContextTranscriptHash(handshakeContext, handshakeContext.MessagesInfo.Count - 1);
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

            var digest = new Cryptography.HashFunctions.Hashes.SHA2_256();
            var key = new PKCS1v2_2API.PrivateKey(new PKCS1v2_2API.PrivateKeyCRT(config.CertificatePrivateKey));
            byte[] signature = PKCS1v2_2API.RSASSA_PSS_SIGN(key, tosign, hashFuncType);


            // var r = System.Security.Cryptography.RSA.Create();
            // r.ImportFromPem(config.RSAPrivateKeyString);

            // return r.SignData(tosign, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pss);

            return signature;
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
                keyShareToSendRawBytes = SEC1_EllipticCurve.EllipticCurvePointToOctetString(ecparams, pointToSend, SEC1_EllipticCurve.ECPointCompression.NotCompressed);
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
                var clientPoint = SEC1_EllipticCurve.OctetStringToEllipticCurvePoint(keyExchangeRawBytes, ecparams.p);

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
            // todo other ciphers than aes_gcm..
            // todo other hash funcs (32 constant for now)
            // need to select valid hash function 
            
            return HkdfExpandLabel(resumptionMasterSecretFromPreviousSession, "resumption", ticketNonce, hashFunction.HashSizeBytes);
        }

        public void SelectCipherSuite(CipherSuite serverHelloSuite)
        {
            this.SetupCryptoAlgorithms(serverHelloSuite);
        }

        public void SelectEcEcdheGroup(SupportedGroupExtension.NamedGroup serverHelloGroup)
        {
            
        }

        public void SelectCipherSuite(ClientHello hello, out bool cipherSuiteOk)
        {
            var supportedCipherSuites = config.CipherSuites; // new CipherSuite[] { CipherSuite.TLS_AES_128_GCM_SHA256 };
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

        public void SelectSigAlgo(ClientHello hello, out bool signAlgoOk)
        {
            var supportedSignAlgo = new SignatureSchemeListExtension.SignatureScheme[] { SignatureSchemeListExtension.SignatureScheme.RsaPssRsaeSha256 };
            var clientSignAlgos = hello.GetExtension<SignatureSchemeListExtension>(ExtensionType.SignatureAlgorithms).Schemes;

            int selectedSignAlgoIdx = -1;

            for (int i = 0; i < supportedSignAlgo.Length && selectedSignAlgoIdx == -1; i++)
                for (int j = 0; j < clientSignAlgos.Length && selectedSignAlgoIdx == -1; j++)
                {
                    if (supportedSignAlgo[i] == clientSignAlgos[j]) selectedSignAlgoIdx = i;
                }

            signAlgoOk = clientSignAlgos.Length > 0 && selectedSignAlgoIdx < supportedSignAlgo.Length && selectedSignAlgoIdx >= 0;

            if (signAlgoOk) this.SelectedSignatureScheme = supportedSignAlgo[selectedSignAlgoIdx];
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

                    serverWriteAead = AEAD_Predefined.Create_AEAD_AES_128_CCM(skey);
                    clientWriteAead = AEAD_Predefined.Create_AEAD_AES_128_CCM(ckey);
                    break;
                case CipherSuite.TLS_AES_256_GCM_SHA384:
                    ckey = HkdfExpandLabel(clientSecret, "key", new byte[0], 32);
                    skey = HkdfExpandLabel(serverSecret, "key", new byte[0], 32);
                    clientWriteIv = HkdfExpandLabel(clientSecret, "iv", new byte[0], 12);
                    serverWriteIv = HkdfExpandLabel(serverSecret, "iv", new byte[0], 12);

                    serverWriteAead = AEAD_Predefined.Create_AEAD_AES_256_GCM(skey);
                    clientWriteAead = AEAD_Predefined.Create_AEAD_AES_256_GCM(ckey);
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

        public byte[] ServerFinished(ByteBuffer handshakeContext)
        {
            byte[] baseKey = currentEndpoint == Endpoint.Server ? ServerHandshakeTrafficSecret : ClientHandshakeTrafficSecret;
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

        public byte[] ComputeBinderValue(ByteBuffer hscontextToBinders, PskTicket ticket)
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
