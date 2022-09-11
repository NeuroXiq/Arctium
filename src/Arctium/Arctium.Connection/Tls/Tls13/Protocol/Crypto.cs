using Arctium.Connection.Tls.Tls13.API;
using Arctium.Connection.Tls.Tls13.Model;
using Arctium.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Cryptography.Ciphers.BlockCiphers;
using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Cryptography.HashFunctions.KDF;
using Arctium.Cryptography.HashFunctions.MAC;
using Arctium.Shared;
using Arctium.Shared.Exceptions;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Standards;
using Arctium.Standards.PKCS1.v2_2;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Arctium.Connection.Tls.Tls13.Protocol
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

        private static readonly byte[] Tls13Label = Encoding.ASCII.GetBytes("tls13 ");

        HashFunction hashFunction;
        HKDF hkdf;
        HMAC hmac;

        byte[] psk;
        byte[] ecdhe_or_dhe;
        private CipherSuite suite;
        private Endpoint currentEndpoint;

        private SupportedGroupExtension.NamedGroup? selectedNamedGroup = null;
        private CipherSuite? selectedCipherSuite = null;
        private SignatureSchemeListExtension.SignatureScheme? selectedSignatureScheme = null;
        private Tls13ServerConfig config;

        public Crypto(Endpoint currentEndpoint, Tls13ServerConfig config)
        {
            this.config = config;
            this.currentEndpoint = currentEndpoint;
            // SetupCryptoAlgorithms(suite, psk, ecdhe_or_dhe);
        }

        public void SetupCryptoAlgorithms(CipherSuite suite, byte[] psk, byte[] ecdhe_or_dhe)
        {
            this.psk = psk;
            this.ecdhe_or_dhe = ecdhe_or_dhe;
            this.suite = suite;

            HashFunction hkdfHashFunc = null;

            switch (suite)
            {
                case CipherSuite.TLS_AES_128_CCM_SHA256:
                case CipherSuite.TLS_AES_128_GCM_SHA256:
                case CipherSuite.TLS_AES_128_CCM_8_SHA256:
                    hashFunction = new SHA2_256();
                    hkdfHashFunc = new SHA2_256();
                    hmac = new HMAC(new SHA2_256(), new byte[0], 0, 0);
                    break;
                case CipherSuite.TLS_AES_256_GCM_SHA384:
                    hashFunction = new SHA2_384();
                    hkdfHashFunc = new SHA2_384();
                    hmac = new HMAC(new SHA2_384(), new byte[0], 0, 0);
                    break;
                case CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
                    throw new NotImplementedException(nameof(CipherSuite.TLS_CHACHA20_POLY1305_SHA256));
                    break;
                default: throw new InvalidOperationException();
            }

            hkdf = new HKDF(new Cryptography.HashFunctions.MAC.HMAC(hkdfHashFunc, new byte[0], 0, 0));
        }

        internal bool VerifyClientFinished(byte[] finishedVerifyDataFromClient, List<KeyValuePair<HandshakeType, byte[]>> handshakeContext)
        {
            return true;
        }

        private Crypto(
            CipherSuite suite,
            byte[] binderKey,
            byte[] clientEarlyTrafficSecret,
            byte[] earlyExporterMasterSecret,
            byte[] clientHandshakeTrafficSecret,
            byte[] serverHandshakeTrafficSecret,
            byte[] clientApplicationTrafficSecret0,
            byte[] serverApplicationTrafficSecret0,
            byte[] exporterMasterSecret,
            byte[] resumptionMasterSecret)
        {
            BinderKey = binderKey;
            ClientEarlyTrafficSecret = clientEarlyTrafficSecret;
            EarlyExporterMasterSecret = earlyExporterMasterSecret;
            ClientHandshakeTrafficSecret = clientHandshakeTrafficSecret;
            ServerHandshakeTrafficSecret = serverHandshakeTrafficSecret;
            ClientApplicationTrafficSecret0 = clientApplicationTrafficSecret0;
            ServerApplicationTrafficSecret0 = serverApplicationTrafficSecret0;
            ExporterMasterSecret = exporterMasterSecret;
            ResumptionMasterSecret = resumptionMasterSecret;
        }

        internal byte[] GenerateServerCertificateVerifySignature(List<KeyValuePair<HandshakeType, byte[]>> handshakeContext)
        {
            if (SelectedSignatureScheme != SignatureSchemeListExtension.SignatureScheme.RsaPssRsaeSha256) throw new Exception();

            // var ext = this.clientHello.GetExtension<SignatureSchemeListExtension>(ExtensionType.SignatureAlgorithms);
            // ext.Schemes.Single(s => s == SignatureSchemeListExtension.SignatureScheme.RsaPssRsaeSha256);


            string contextStr = "TLS 1.3, server CertificateVerify";
            byte[] stringBytes = Encoding.ASCII.GetBytes(contextStr);

            List<byte[]> tohash = new List<byte[]>();

            tohash.AddRange(handshakeContext.Select(x => x.Value));
            // tohash.Add(this.serverConfig.DerEncodedCertificateBytes);

            byte[] hash = TranscriptHash(tohash.ToArray());

            byte[] tosign = new byte[64 + stringBytes.Length + 1 + hash.Length];

            int c = 0;

            MemOps.Memset(tosign, 0, 64, 0x20);
            c += 64;
            MemCpy.Copy(stringBytes, 0, tosign, c, stringBytes.Length);
            c += stringBytes.Length;
            tosign[c] = 0;
            c += 1;

            MemCpy.Copy(hash, 0, tosign, c, hash.Length);

            var key = new PKCS1v2_2API.PrivateKey(new PKCS1v2_2API.PrivateKeyCRT(config.CertificatePrivateKey));
            byte[] signature = PKCS1v2_2API.RSASSA_PSS_SIGN(key, tosign, hash.Length, new Cryptography.HashFunctions.Hashes.SHA2_256());

            return signature;
        }

        public void InitMasterSecret2(List<KeyValuePair<HandshakeType, byte[]>> handshakeContext)
        {
            ByteBuffer ch_sf = new ByteBuffer();
            ByteBuffer ch_cf = new ByteBuffer();

            for (int i = 0; i < handshakeContext.Count; i++)
            {
                ch_cf.Append(handshakeContext[i].Value);

                if (i < handshakeContext.Count - 1)
                {
                    ch_sf.Append(handshakeContext[i].Value);
                }
            }

            byte[] ch_sf_bytes = MemCpy.CopyToNewArray(ch_sf.Buffer, 0, ch_sf.DataLength);
            byte[] ch_cf_bytes = MemCpy.CopyToNewArray(ch_cf.Buffer, 0, ch_cf.DataLength);

            InitMasterSecret(ch_sf_bytes, ch_cf_bytes);
        }

        public void InitMasterSecret(byte[] clienthello_serverfinished, byte[] clienthello_clientfinished)
        {
            byte[] derived = DeriveSecret(HandshakeSecret, "derived", new byte[0]);
            byte[] zeroValueOfHashLen = new byte[hashFunction.HashSizeBytes];
            MasterSecret = new byte[this.hashFunction.HashSizeBytes];

            hkdf.Extract(derived, zeroValueOfHashLen, MasterSecret);

            ClientApplicationTrafficSecret0 = DeriveSecret(MasterSecret, "c ap traffic", clienthello_serverfinished);
            ServerApplicationTrafficSecret0 = DeriveSecret(MasterSecret, "s ap traffic", clienthello_serverfinished);
            ExporterMasterSecret = DeriveSecret(MasterSecret, "exp master", clienthello_serverfinished);
            ResumptionMasterSecret = DeriveSecret(MasterSecret, "res master", clienthello_clientfinished);
        }

        public byte[] GenerateSharedSecretAndGetKeyShareToSend(KeyShareEntry clientKeyShareEntry)
        {
            if (clientKeyShareEntry.NamedGroup != SelectedNamedGroup) throw new Tls13Exception("internal: trying to compute other than selected");

            byte[] privKey = new byte[32];
            GlobalConfig.RandomGeneratorCryptSecure(privKey, 0, 32);

            byte[] keyToSend = RFC7748.X25519_UCoord_9(privKey);

            byte[] sharedSecret = RFC7748.X25519(privKey, clientKeyShareEntry.KeyExchangeRawBytes);
            var keyShare = new KeyShareServerHelloExtension(new KeyShareEntry(SupportedGroupExtension.NamedGroup.X25519, keyToSend));

            this.ecdhe_or_dhe = sharedSecret;

            return keyToSend;
        }

        public void asdf(ClientHello clientHello)
        { }

        public void SelectSuiteAndEcEcdheGroupAndSigAlgo(ClientHello hello, out bool groupOk, out bool cipherSuiteOk, out bool signAlgoOk)
        {
            var supportedGroups = new SupportedGroupExtension.NamedGroup[] { SupportedGroupExtension.NamedGroup.X25519 };
            var supportedCipherSuites = new CipherSuite[] { CipherSuite.TLS_AES_128_GCM_SHA256 };
            var supportedSignAlgo = new SignatureSchemeListExtension.SignatureScheme[] { SignatureSchemeListExtension.SignatureScheme.RsaPssRsaeSha256 };

            var clientGroups = hello.GetExtension<SupportedGroupExtension>(ExtensionType.SupportedGroups).NamedGroupList;
            var clientCiphers = hello.CipherSuites;
            var clientSignAlgos = hello.GetExtension<SignatureSchemeListExtension>(ExtensionType.SignatureAlgorithms).Schemes;

            int selectedGroupIdx = -1, selectedCipherSuiteIdx = -1, selectedSignAlgoIdx = -1;

            for (int i = 0; i < supportedGroups.Length && selectedGroupIdx == -1; i++)
                for (int j = 0; j < clientGroups.Length && selectedGroupIdx == -1; j++)
                {
                    if(supportedGroups[i] == clientGroups[j]) selectedGroupIdx = i;
                }

            for (int i = 0; i < supportedCipherSuites.Length && selectedCipherSuiteIdx == -1; i++)
                for (int j = 0; j < clientCiphers.Length && selectedCipherSuiteIdx == -1; j++)
                {
                    if (supportedCipherSuites[i] == clientCiphers[j]) selectedCipherSuiteIdx = i;
                }

            for (int i = 0; i < supportedSignAlgo.Length && selectedSignAlgoIdx == -1; i++)
                for (int j = 0; j < clientSignAlgos.Length && selectedSignAlgoIdx == -1; j++)
                {
                    if (supportedSignAlgo[i] == clientSignAlgos[j]) selectedSignAlgoIdx = i;
                }

            groupOk = clientGroups.Length > 0 && selectedGroupIdx < supportedGroups.Length;
            cipherSuiteOk = clientCiphers.Length > 0 && selectedCipherSuiteIdx < supportedCipherSuites.Length;
            signAlgoOk = clientSignAlgos.Length > 0 && selectedSignAlgoIdx < supportedSignAlgo.Length;


            if (groupOk) this.SelectedNamedGroup = supportedGroups[selectedGroupIdx];
            if (cipherSuiteOk) this.SelectedCipherSuite = supportedCipherSuites[selectedCipherSuiteIdx];
            if (signAlgoOk) this.SelectedSignatureScheme = supportedSignAlgo[selectedSignAlgoIdx];

            SetupCryptoAlgorithms(SelectedCipherSuite, null, null);
        }

        public byte[] TranscriptHash(params byte[][] m)
        {
            hashFunction.Reset();

            foreach (byte[] buf in m) hashFunction.HashBytes(buf);

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

            byte[] clientWriteIv, serverWriteIv;
            AEAD serverWriteAead, clientWriteAead;

            switch (SelectedCipherSuite)
            {
                case CipherSuite.TLS_AES_128_GCM_SHA256:
                    byte[] ckey = HkdfExpandLabel(clientSecret, "key", new byte[0], 16);
                    byte[] skey = HkdfExpandLabel(serverSecret, "key", new byte[0], 16);
                    clientWriteIv = HkdfExpandLabel(clientSecret, "iv", new byte[0], 12);
                    serverWriteIv = HkdfExpandLabel(serverSecret, "iv", new byte[0], 12);

                    serverWriteAead = new GaloisCounterMode(new AES(skey), 16);
                    clientWriteAead = new GaloisCounterMode(new AES(ckey), 16);
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
        
        public void InitEarlySecret(byte[] clientHello)
        {
            byte[] zeroValueOfHashLen = new byte[hashFunction.HashSizeBytes];
            byte[] pskSecret = this.psk != null ? psk : zeroValueOfHashLen;
            EarlySecret = new byte[this.hashFunction.HashSizeBytes];


            bool externalBinder = false; // ? 

            hkdf.Extract(zeroValueOfHashLen, pskSecret, EarlySecret);

            BinderKey = DeriveSecret(EarlySecret, externalBinder ? "ext binder" : "res binder", new byte[0]);

            ClientEarlyTrafficSecret = DeriveSecret(EarlySecret, "c e traffic", clientHello);
        }

        public void InitHandshakeSecret(List<byte[]> messages)
        {
            byte[] buf = new byte[messages[0].Length + messages[1].Length];
            MemCpy.Copy(messages[0], 0, buf, 0, messages[0].Length);
            MemCpy.Copy(messages[1], 0, buf, messages[0].Length, messages[1].Length);

            byte[] derived = DeriveSecret(EarlySecret, "derived", new byte[0]);

            HandshakeSecret = new byte[hashFunction.HashSizeBytes];
            hkdf.Extract(derived, this.ecdhe_or_dhe, HandshakeSecret);

            ClientHandshakeTrafficSecret = DeriveSecret(HandshakeSecret, "c hs traffic", buf);
            ServerHandshakeTrafficSecret = DeriveSecret(HandshakeSecret, "s hs traffic", buf);
        }

        public byte[] ServerFinished(List<byte[]> handshakeContext)
        {
            byte[] baseKey = ServerHandshakeTrafficSecret;
            byte[] finishedKey = HkdfExpandLabel(baseKey, "finished", new byte[0], hashFunction.HashSizeBytes);
            byte[] result = new byte[hmac.HashFunctionHashSizeBytes];

            hmac.Reset();

            hmac.ChangeKey(finishedKey);
            hmac.ProcessBytes(TranscriptHash(handshakeContext.ToArray()));

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

        byte[] HkdfExpandLabel(byte[] secret, string labelText, byte[] context, int length)
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

        byte[] DeriveSecret(byte[] secret, string label, byte[] messages)
        {
            return HkdfExpandLabel(secret, label, TranscriptHash(messages), hashFunction.HashSizeBytes);
        }
    }
}
