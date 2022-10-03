﻿using Arctium.Standards.Connection.Tls.Tls13.API;
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
        byte[] EarlySecret;
        byte[] HandshakeSecret;
        byte[] MasterSecret;

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
        private string selectedCipherSuiteHashFunctionName = null;
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
            this.psk = psk;
            //this.Ecdhe_or_dhe_SharedSecret = ecdhe_or_dhe;
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
            selectedCipherSuiteHashFunctionName = hashFunction.GetType().Name;
            selectedCipherSuite = suite;
        }

        internal bool VerifyClientFinished(byte[] finishedVerifyDataFromClient, HandshakeContext handshakeContext)
        {
            return true;
        }

        internal byte[] GenerateServerCertificateVerifySignature(HandshakeContext handshakeContext)
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
             byte[] hash = HandshakeContextTranscriptHash(handshakeContext, handshakeContext.MessagesInfo.Count - 1);

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

        public void InitMasterSecret2(HandshakeContext handshakeContext)
        {

            int sfIdx = -1;

            for (int i = 0; i < handshakeContext.MessagesInfo.Count && sfIdx == -1; i++)
                if (handshakeContext.MessagesInfo[i].HandshakeType == HandshakeType.Finished) sfIdx = i;

            byte[] ch_sf_bytes = MemCpy.CopyToNewArray(handshakeContext.HandshakeMessages, 0, handshakeContext.MessagesInfo[sfIdx].LengthTo);
            byte[] ch_cf_bytes = MemCpy.CopyToNewArray(handshakeContext.HandshakeMessages, 0, handshakeContext.MessagesInfo[handshakeContext.MessagesInfo.Count - 1].LengthTo);

            InitMasterSecret(handshakeContext);
        }

        public void InitMasterSecret(HandshakeContext hcontext)
        {
            byte[] derived = DeriveSecret(HandshakeSecret, "derived", new byte[0]);
            byte[] zeroValueOfHashLen = new byte[hashFunction.HashSizeBytes];
            MasterSecret = new byte[this.hashFunction.HashSizeBytes];

            hkdf.Extract(derived, zeroValueOfHashLen, MasterSecret);

            int sf = -1, cf = -1;

            for (int i = 0; i < hcontext.MessagesInfo.Count && (sf == -1 || cf == -1); i++)
            {
                if (hcontext.MessagesInfo[i].HandshakeType == HandshakeType.Finished)
                {
                    if (sf == -1) sf = i;
                    else if (cf == -1) { cf = i; }
                    else Validation.ThrowInternal("");
                }
            }

            if (sf == -1 || cf == -1) Validation.ThrowInternal("");

            ClientApplicationTrafficSecret0 = DeriveSecret(MasterSecret, "c ap traffic", hcontext, sf);
            ServerApplicationTrafficSecret0 = DeriveSecret(MasterSecret, "s ap traffic", hcontext, sf);
            ExporterMasterSecret = DeriveSecret(MasterSecret, "exp master", hcontext, cf);
            ResumptionMasterSecret = DeriveSecret(MasterSecret, "res master", hcontext, cf);
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

        //public byte[] GenerateSharedSecretAndGetKeyShareToSend(KeyShareEntry clientKeyShareEntry)
        //{
        //    if (clientKeyShareEntry.NamedGroup != SelectedNamedGroup) throw new ArctiumExceptionInternal();

        //    var clientShare = clientKeyShareEntry;
        //    KeyShareServerHelloExtension keyShare = null;
        //    byte[] keyToSend = null;


        //}

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

        public void asdf(ClientHello clientHello)
        { }

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

        public void SelectSuiteAndEcEcdheGroupAndSigAlgo(ClientHello hello, out bool groupOk, out bool cipherSuiteOk, out bool signAlgoOk)
        {
            SelectCipherSuite(hello, out cipherSuiteOk);
            SelectSigAlgo(hello, out signAlgoOk);
            SelectEcEcdheGroup(hello, out groupOk);

            if (cipherSuiteOk) SetupCryptoAlgorithms(SelectedCipherSuite);
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
        
        public void InitEarlySecret(HandshakeContext handshakeContext, byte[] psk)
        {
            byte[] zeroValueOfHashLen = new byte[hashFunction.HashSizeBytes];
            this.psk = psk;
            byte[] pskSecret = this.psk != null ? psk : zeroValueOfHashLen;
            EarlySecret = new byte[this.hashFunction.HashSizeBytes];

            bool externalBinder = false; // ? 

            hkdf.Extract(zeroValueOfHashLen, pskSecret, EarlySecret);

            BinderKey = DeriveSecret(EarlySecret, externalBinder ? "ext binder" : "res binder", new byte[0]);

            ClientEarlyTrafficSecret = DeriveSecret(EarlySecret, "c e traffic", handshakeContext, 0);
        }

        public void InitHandshakeSecret(HandshakeContext handshakeContext)
        {
            // byte[] buf = new byte[messages[0].Length + messages[1].Length];
            // MemCpy.Copy(messages[0], 0, buf, 0, messages[0].Length);
            // MemCpy.Copy(messages[1], 0, buf, messages[0].Length, messages[1].Length);

            // second server hello (skip helloretryrequest)
            int sh2OrSh1 = handshakeContext.MessagesInfo.FindLastIndex(x => x.HandshakeType == HandshakeType.ServerHello);

            // byte[] buf = MemCpy.CopyToNewArray(handshakeContext.HandshakeMessages, 0, handshakeContext.MessagesInfo[1].LengthTo);

            byte[] derived = DeriveSecret(EarlySecret, "derived", new byte[0]);

            HandshakeSecret = new byte[hashFunction.HashSizeBytes];
            hkdf.Extract(derived, this.Ecdhe_or_dhe_SharedSecret, HandshakeSecret);

            // ClientHandshakeTrafficSecret = DeriveSecret(HandshakeSecret, "c hs traffic", buf);
            // ServerHandshakeTrafficSecret = DeriveSecret(HandshakeSecret, "s hs traffic", buf);

            ClientHandshakeTrafficSecret = DeriveSecret(HandshakeSecret, "c hs traffic", handshakeContext, sh2OrSh1);
            ServerHandshakeTrafficSecret = DeriveSecret(HandshakeSecret, "s hs traffic", handshakeContext, sh2OrSh1);
        }

        public byte[] ServerFinished(HandshakeContext handshakeContext)
        {
            byte[] baseKey = currentEndpoint == Endpoint.Server ? ServerHandshakeTrafficSecret : ClientHandshakeTrafficSecret;
            byte[] finishedKey = HkdfExpandLabel(baseKey, "finished", new byte[0], hashFunction.HashSizeBytes);
            byte[] result = new byte[hmac.HashFunctionHashSizeBytes];

            hmac.Reset();
            
            hmac.ChangeKey(finishedKey);
            hmac.ProcessBytes(HandshakeContextTranscriptHash(handshakeContext, handshakeContext.MessagesInfo.Count - 1));
            // hmac.ProcessBytes(TranscriptHash(MemCpy.CopyToNewArray(handshakeContext.HandshakeMessages, 0, handshakeContext.TotalLength)));

            hmac.Final(result, 0);

            return result;
        }

        public bool IsPskBinderValueValid(HandshakeContext handshakeContext,
            PskTicket ticket,
            byte[] clientBinderValue)
        {
            if (psk == null) throw new ArctiumExceptionInternal("psk must be set");

            var hash = HandshakeContextTranscriptHash(handshakeContext, -1, true);
            byte[] result = new byte[hash.Length];

            byte[] binderKey = HkdfExpandLabel(BinderKey, "finished", new byte[0], hashFunction.HashSizeBytes);

            hmac.Reset();
            hmac.ChangeKey(binderKey);
            hmac.ProcessBytes(hash);
            hmac.Final(result, 0);

            return MemOps.Memcmp(result, clientBinderValue);
        }

        public byte[] GenerateBinderKey(byte[] psk, HKDF hkdf, int hashSizeBytes)
        {
            byte[] zeroValueOfHashLen = new byte[hashFunction.HashSizeBytes];
            this.psk = psk;
            byte[] pskSecret = this.psk != null ? psk : zeroValueOfHashLen;
            var earlySecret = new byte[this.hashFunction.HashSizeBytes];

            bool externalBinder = false; // ? 

            hkdf.Extract(zeroValueOfHashLen, pskSecret, earlySecret);

            // BinderKey = DeriveSecret(EarlySecret, externalBinder ? "ext binder" : "res binder", new byte[0]);
            var binderKey = HkdfExpandLabel(hkdf, earlySecret, externalBinder ? "ext binder" : "res binder", new byte[0], hashSizeBytes);

            return binderKey;
        }

        public byte[] ComputeBinderValue(HandshakeContext hscontext, PskTicket ticket)
        {
            byte[] psk = GeneratePsk(ticket.ResumptionMasterSecret, ticket.TicketNonce);

            var hashFunc = CryptoAlgoFactory.CreateHashFunction(ticket.HashFunctionId);
            var hkdf = new HKDF(new HMAC(CryptoAlgoFactory.CreateHashFunction(ticket.HashFunctionId), new byte[0], 0, 0));
            var hmac = new HMAC(CryptoAlgoFactory.CreateHashFunction(ticket.HashFunctionId), new byte[0], 0, 0);

            var binderKey = GenerateBinderKey(psk, hkdf, hashFunc.HashSizeBytes);
            var hash = HandshakeContextTranscriptHash(hashFunc, hscontext, -1, true);

            byte[] result = new byte[hashFunc.HashSizeBytes];

            hmac.Reset();
            hmac.ChangeKey(binderKey);
            hmac.ProcessBytes(hash);
            hmac.Final(result, 0);

            return result;
        }

        public void ClientFinished()
        {
            throw new NotImplementedException();
        }

        public void PostHandshakeFinished()
        {
            throw new Exception();
        }

        private byte[] HandshakeContextTranscriptHash(HandshakeContext handshakeContext, int indexLastMsgToInclude, bool forPskBinders = false)
        {
            return HandshakeContextTranscriptHash(this.hashFunction, handshakeContext, indexLastMsgToInclude, forPskBinders);
        }

        private byte[] HandshakeContextTranscriptHash(HashFunction hashFunction, HandshakeContext handshakeContext, int indexLastMsgToInclude, bool forPskBinders = false)
        {
            // todo clean up needed here
            bool ch2 = false;
            int chCount = 0;


            for (int i = 0; i <= indexLastMsgToInclude; i++)
                if (handshakeContext.MessagesInfo[i].HandshakeType == HandshakeType.ClientHello) chCount++;

            if (forPskBinders) chCount = handshakeContext.MessagesInfo.Count(m => m.HandshakeType == HandshakeType.ClientHello);

            ch2 = chCount == 2;
            int clientHello1Len = -1;
            hashFunction.Reset();

            if (forPskBinders)
            {
                if (!ch2)
                {
                    hashFunction.HashBytes(handshakeContext.HandshakeMessages, 0, handshakeContext.LengthToPskBinders);
                    return hashFunction.HashFinal();
                }

                clientHello1Len = handshakeContext.MessagesInfo[0].LengthTo;
                byte[] tempCh1 = new byte[4];

                tempCh1[0] = (byte)HandshakeType.MessageHash;
                MemMap.ToBytes1UShortBE((ushort)hashFunction.HashSizeBytes, tempCh1, 2);

                hashFunction.HashBytes(handshakeContext.HandshakeMessages, 0, handshakeContext.MessagesInfo[0].LengthTo);
                byte[] clientHello1Hash = hashFunction.HashFinal();

                hashFunction.Reset();
                hashFunction.HashBytes(tempCh1);
                hashFunction.HashBytes(clientHello1Hash);
                hashFunction.HashBytes(handshakeContext.HandshakeMessages, clientHello1Len, handshakeContext.LengthToPskBinders - clientHello1Len);

                return hashFunction.HashFinal();
            }

            // special case when helloretryrequest (so two clienthello in context)
            if (ch2)
            {
                byte[] tempCh1 = new byte[4];

                tempCh1[0] = (byte)HandshakeType.MessageHash;
                MemMap.ToBytes1UShortBE((ushort)hashFunction.HashSizeBytes, tempCh1, 2);

                hashFunction.HashBytes(handshakeContext.HandshakeMessages, 0, handshakeContext.MessagesInfo[0].LengthTo);
                byte[] clientHello1Hash = hashFunction.HashFinal();

                hashFunction.Reset();
                hashFunction.HashBytes(tempCh1);
                hashFunction.HashBytes(clientHello1Hash);
            }
            else
            {
                // not special case just hash
                hashFunction.HashBytes(handshakeContext.HandshakeMessages, 0, handshakeContext.MessagesInfo[0].LengthTo);
            }

            // hash everything but not first message (CH 1) because can be special case as above
            clientHello1Len = handshakeContext.MessagesInfo[0].Length;

            int length = handshakeContext.MessagesInfo[indexLastMsgToInclude].LengthTo - clientHello1Len;

            hashFunction.HashBytes(handshakeContext.HandshakeMessages, clientHello1Len, length);

            return hashFunction.HashFinal();
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

        byte[] HkdfExpandLabel_org(byte[] secret, string labelText, byte[] context, int length)
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


            hkdf.Expand(secret, label, result, length);

            return result;
        }

        byte[] DeriveSecret(byte[] secret, string label, HandshakeContext handshakeContext, int hContextLastMsgIndex)
        {
            return HkdfExpandLabel(secret, label, HandshakeContextTranscriptHash(handshakeContext, hContextLastMsgIndex), hashFunction.HashSizeBytes);
        }

        byte[] DeriveSecret(byte[] secret, string label, byte[] messages)
        {
            return HkdfExpandLabel(secret, label, TranscriptHash(messages), hashFunction.HashSizeBytes);
        }
    }
}
