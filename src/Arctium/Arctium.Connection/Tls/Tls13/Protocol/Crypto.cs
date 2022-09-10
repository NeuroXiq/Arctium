using Arctium.Connection.Tls.Tls13.Model;
using Arctium.Cryptography.Ciphers.BlockCiphers;
using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Cryptography.HashFunctions.KDF;
using Arctium.Cryptography.HashFunctions.MAC;
using Arctium.Shared.Helpers.Buffers;
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

        public struct Message
        {
            public byte[] Bytes;
            public HandshakeType Type;
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

        private static readonly byte[] Tls13Label = Encoding.ASCII.GetBytes("tls13 ");

        HashFunction hashFunction;
        HKDF hkdf;
        HMAC hmac;

        byte[] psk;
        byte[] ecdhe_or_dhe;
        private CipherSuite suite;
        private Endpoint currentEndpoint;

        public Crypto(Endpoint currentEndpoint)
        {
            this.currentEndpoint = currentEndpoint;
            SetupCryptoAlgorithms(suite, psk, ecdhe_or_dhe);
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

            switch (this.suite)
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


        byte[] Merge(byte[][] arrays)
        {
            int len = arrays.Select(x => x.Length).Sum();
            byte[] r = new byte[len];

            int q = 0;

            for (int i = 0; i < arrays.Length; i++)
            {
                var t = arrays[i];

                MemCpy.Copy(t, 0, r, q, t.Length);
                q += t.Length;
            }

            return r;
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
