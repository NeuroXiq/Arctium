using Arctium.Cryptography.Ciphers.BlockCiphers;
using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Cryptography.HashFunctions.KDF;
using Arctium.Cryptography.HashFunctions.MAC;
using Arctium.Standards.Connection.QUICv1Impl.Model;
using Arctium.Standards.Connection.Tls13Impl.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Standards.Connection.QUICv1Impl
{
    internal class QuicCrypto
    {
        static readonly ReadOnlyMemory<byte> InitialSaltHKDFExtract = new byte[] { 0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17,0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a };
        
        CipherSuite cipherSuite;
        byte[] clientInitialSecret;
        byte[] serverInitialSecret;
        private byte[] clientKey;
        private byte[] serverKey;
        byte[] clientHp;
        byte[] serverHp;
        byte[] clientIv;
        byte[] serverIv;
        byte[] headerMask;

        public QuicCrypto()
        {
            // SetupInitCrypto();
        }

        public void HeaderProtectionDecrypt(byte[] buffer, int offs)
        {
            int offsetPacketNumber = QuicModelCoding.GetOffsetLHPPacketNumberField(buffer, offs);
            int sampleOffset = offsetPacketNumber + 4;
            
        }

        private void HeaderProtection(byte[] key, byte[] sampleInput, byte[] sampleOffset)
        {
            var aes = new AES(key);
            headerMask = new byte[16];
            aes.Encrypt(sampleInput, 0, headerMask, 0, 16);
        }

        private void GetHKDF() { }

        public void SetupInitCrypto(Memory<byte> destinationConnectionId)
        {
            //byte[] testDestConId = new byte[] { 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
            //destinationConnectionId = testDestConId.ToArray();

            cipherSuite = CipherSuite.TLS_AES_128_GCM_SHA256;
            var hkdf = new HKDF(new HMAC(new SHA2_256(), new byte[0], 0, 0));
            byte[] initialSecret = new byte[32];
            hkdf.Extract(InitialSaltHKDFExtract.ToArray(), destinationConnectionId.ToArray(), initialSecret);
            clientInitialSecret = Tls13Impl.Protocol.Crypto.HkdfExpandLabel(hkdf, initialSecret, "client in", new byte[0], 32);
            serverInitialSecret = Tls13Impl.Protocol.Crypto.HkdfExpandLabel(hkdf, initialSecret, "server in", new byte[0], 32);

            clientKey = Tls13Impl.Protocol.Crypto.HkdfExpandLabel(hkdf, clientInitialSecret, "quic key", new byte[0], 16);
            serverKey = Tls13Impl.Protocol.Crypto.HkdfExpandLabel(hkdf, serverInitialSecret, "quic key", new byte[0], 16);

            clientHp = Tls13Impl.Protocol.Crypto.HkdfExpandLabel(hkdf, clientInitialSecret, "quic hp", new byte[0], 16);
            serverHp = Tls13Impl.Protocol.Crypto.HkdfExpandLabel(hkdf, serverInitialSecret, "quic hp", new byte[0], 16);
            
            clientIv = Tls13Impl.Protocol.Crypto.HkdfExpandLabel(hkdf, clientInitialSecret, "quic iv", new byte[0], 12);
            serverIv = Tls13Impl.Protocol.Crypto.HkdfExpandLabel(hkdf, serverInitialSecret, "quic iv", new byte[0], 12);
        }
    }
}
