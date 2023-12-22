using Arctium.Cryptography.Ciphers.BlockCiphers;
using Arctium.Cryptography.Ciphers.StreamCiphers;
using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Cryptography.HashFunctions.KDF;
using Arctium.Cryptography.HashFunctions.MAC;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Standards.Connection.QUICv1;
using Arctium.Standards.Connection.QUICv1Impl.Model;
using Arctium.Standards.Connection.Tls.Configuration.TlsExtensions;
using Arctium.Standards.Connection.Tls13Impl.Model;
using Arctium.Standards.Connection.Tls13Impl.Protocol;
using Arctium.Standards.RFC;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Standards.Connection.QUICv1Impl
{
    internal class QuicCrypto
    {
        public int WriteAuthTagLen { get { return writeAead.AuthenticationTagLengthBytes; } }

        static readonly ReadOnlyMemory<byte> InitialSaltHKDFExtract = new byte[] { 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a };

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
        byte[] clientNonce;
        byte[] serverNonce;
        byte[] nonce;

        AES clientHpAES;
        AES serverHpAES;
        ChaCha20 clientHpChacha;
        ChaCha20 serverHpChacha;

        private AEAD clientAead;
        private AEAD serverAead;

        AES readHtpAes { get { return endpoint == EndpointType.Server ? clientHpAES : serverHpAES; } }
        AES writeHtpAes { get { return endpoint == EndpointType.Server ? serverHpAES : clientHpAES; } }
        ChaCha20 readHtpChacha { get { return endpoint == EndpointType.Server ? clientHpChacha : serverHpChacha; } }
        ChaCha20 writeHtpChacha { get { return endpoint == EndpointType.Server ? serverHpChacha : clientHpChacha; } }
        AEAD readAead { get { return endpoint == EndpointType.Server ? clientAead : serverAead; } }
        AEAD writeAead { get { return endpoint == EndpointType.Server ? serverAead : clientAead; } }
        byte[] writeIv { get { return endpoint == EndpointType.Server ? serverIv : clientIv; } }
        byte[] readIv { get { return endpoint == EndpointType.Server ? clientIv : serverIv; } }

        public QuicCrypto(EndpointType endpoint)
        {
            this.endpoint = endpoint;
            // SetupInitCrypto();
        }

        byte[] plainPacket = new byte[]
            { 0xc3,0x00,0x00,0x00,0x01,0x08,0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08,0x00,0x00,0x44,0x9e,0x00,0x00,0x00,0x02,0x06,0x00,0x40,0xf1,0x01,0x00,0x00,0xed,0x03,0x03,0xeb,0xf8,0xfa,0x56,0xf1,0x29,0x39,0xb9,0x58,0x4a,0x38,0x96,0x47,0x2e,0xc4,0x0b,0xb8,0x63,0xcf,0xd3,0xe8,0x68,0x04,0xfe,0x3a,0x47,0xf0,0x6a,0x2b,0x69,0x48,0x4c,0x00,0x00,0x04,0x13,0x01,0x13,0x02,0x01,0x00,0x00,0xc0,0x00,0x00,0x00,0x10,0x00,0x0e,0x00,0x00,0x0b,0x65,0x78,0x61,0x6d,0x70,0x6c,0x65,0x2e,0x63,0x6f,0x6d,0xff,0x01,0x00,0x01,0x00,0x00,0x0a,0x00,0x08,0x00,0x06,0x00,0x1d,0x00,0x17,0x00,0x18,0x00,0x10,0x00,0x07,0x00,0x05,0x04,0x61,0x6c,0x70,0x6e,0x00,0x05,0x00,0x05,0x01,0x00,0x00,0x00,0x00,0x00,0x33,0x00,0x26,0x00,0x24,0x00,0x1d,0x00,0x20,0x93,0x70,0xb2,0xc9,0xca,0xa4,0x7f,0xba,0xba,0xf4,0x55,0x9f,0xed,0xba,0x75,0x3d,0xe1,0x71,0xfa,0x71,0xf5,0x0f,0x1c,0xe1,0x5d,0x43,0xe9,0x94,0xec,0x74,0xd7,0x48,0x00,0x2b,0x00,0x03,0x02,0x03,0x04,0x00,0x0d,0x00,0x10,0x00,0x0e,0x04,0x03,0x05,0x03,0x06,0x03,0x02,0x03,0x08,0x04,0x08,0x05,0x08,0x06,0x00,0x2d,0x00,0x02,0x01,0x01,0x00,0x1c,0x00,0x02,0x40,0x01,0x00,0x39,0x00,0x32,0x04,0x08,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x05,0x04,0x80,0x00,0xff,0xff,0x07,0x04,0x80,0x00,0xff,0xff,0x08,0x01,0x10,0x01,0x04,0x80,0x00,0x75,0x30,0x09,0x01,0x10,0x0f,0x08,0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08,0x06,0x04,0x80,0x00,0xff,0xff};
        
        private EndpointType endpoint;

        void GetPacketDataForCrypto(
            byte[] p,
            int o,
            out uint packetNumber,
            out int pnBytesCount,
            out int oPacketNumber)
        {
            if ((p[o] & 0x80) != 0)
            {
                // lhp
                var r = QuicModelCoding.DecodeLHP(p, o, false, true);

                packetNumber = r.PacketNumber;
                pnBytesCount = r.PacketNumberLength + 1;
                oPacketNumber = r.A_OffsetPacketNumber;
            }
            else throw new NotImplementedException();
        }

        public int EncryptPacket(
            byte[] header,
            int headerOffset,
            int headerLen,
            byte[] payload,
            int payloadOffset,
            int payloadLen,
            byte[] output,
            int outOffset)
        {
            GetPacketDataForCrypto(
                header,
                headerOffset,
                out var packetNumber,
                out var pnBytesCount,
                out var oPacketNumber);

            ComputeWriteNonce(packetNumber);

            int oPayload = outOffset + headerLen;
            int oAuthTag = oPayload + payloadLen;

            writeAead.AuthenticatedEncryption(
                nonce, 0, nonce.Length,
                payload, payloadOffset, payloadLen,
                header, headerOffset, headerLen,
                output, oPayload,
                output, oAuthTag);

            // header protection
            MemCpy.Copy(header, headerOffset, output, outOffset, headerLen);
            int sampleOffset = oPacketNumber + outOffset + 4;
            ComputeWriteMask(output, sampleOffset);

            // writeHtpAes.Encrypt(output, sampleOffset, headerMask, 0, headerMask.Length);
            int o = outOffset;
            byte[] buffer = output;
            byte[] mask = headerMask;

            if ((buffer[o] & 0x80) != 0)
            {
                buffer[o] ^= (byte)(mask[0] & 0x0f);
            }
            else
            {
                throw new NotImplementedException(); // todo offsets;
                buffer[o] ^= (byte)(mask[0] & 0x1f);
            }

            for (int i = 0; i < pnBytesCount; i++)
                buffer[oPacketNumber + i] ^= mask[i + 1];

            return writeAead.AuthenticationTagLengthBytes + headerLen + payloadLen;
        }

        void ComputeWriteNonce(uint packetNumber)
        {
            MemCpy.Copy(writeIv, 0, nonce, 0, writeIv.Length);
            for (int i = 0; i < 4; i++)
                nonce[nonce.Length - 1 - i] ^= (byte)(packetNumber >> (8 * i));
        }

        void ComputeReadNonce(uint packetNumber)
        {
            MemCpy.Copy(readIv, 0, nonce, 0, readIv.Length);
            for (int i = 0; i < 4; i++)
                nonce[nonce.Length - 1 - i] ^= (byte)(packetNumber >> (8 * i));
        }

        public void DecryptPacket(byte[] buffer, int offset, byte[] output, int outOffs)
        {
            // 1. decrypt packet header
            // 2. decrypt packet payload
            // 3. copy decrypted header to output (at start)

            HeaderProtectionDecrypt(buffer, offset);
            
            var lhp = QuicModelCoding.DecodeLHP(buffer, offset, false);

            ComputeReadNonce(lhp.PacketNumber);

            int decryptedPayloadOffs = lhp.A_HeaderLength;
            int encryptedPayloadOffs = offset + lhp.A_HeaderLength;
            int encryptedPayloadLen = lhp.Payload.Length - 16;
            int atagOffs = offset + lhp.A_HeaderLength + lhp.Payload.Length - 16;
            byte[] decryptedPayload = output;
            
            readAead.AuthenticatedDecryption(
                nonce, 0, nonce.Length,
                buffer, encryptedPayloadOffs, encryptedPayloadLen,
                buffer, offset, lhp.A_HeaderLength,
                decryptedPayload, decryptedPayloadOffs,
                buffer, atagOffs,
                out var ok);

            MemCpy.Copy(buffer, offset, output, outOffs, lhp.A_HeaderLength);

            if (!ok) throw new QuicException("AEAD auth tag not ok");
        }

        private void ComputeReadMask(byte[] buffer, int sampleOffset)
        {
            byte[] mask = this.headerMask;

            if (readHtpAes != null)
            {
                readHtpAes.Encrypt(buffer, sampleOffset, mask, 0, 16);
            }
            else if (readHtpChacha != null)
            {
                throw new NotImplementedException();
            }
            else throw new Exception("internal");
        }

        private void ComputeWriteMask(byte[] buffer, int sampleOffset)
        {
            byte[] mask = this.headerMask;

            if (writeHtpAes != null)
            {
                writeHtpAes.Encrypt(buffer, sampleOffset, mask, 0, 16);
            }
            else if (writeHtpAes != null)
            {
                throw new Exception("internal");
            }
            else throw new Exception("internal");
        }

        private void HeaderProtectionDecrypt(byte[] buffer, int offset)
        {
            // todo must work with short header packet
            var lhp = QuicModelCoding.DecodeLHP(buffer, offset, true);
            int o = offset;
            int offsetPacketNumber = lhp.A_OffsetPacketNumber;
            int sampleOffset = lhp.A_OffsetPacketNumber + 4;

            ComputeReadMask(buffer, sampleOffset);
            byte[] mask = headerMask;

            if ((buffer[o] & 0x80) != 0)
            {
                buffer[o] ^= (byte)(mask[0] & 0x0f);
            }
            else
            {
                buffer[o] ^= (byte)(mask[0] & 0x1f);
            }

            int pnlength = (buffer[o] & 0x03) + 1;
            
            for (int i = 0; i < pnlength; i++)
                buffer[offsetPacketNumber + i] ^= mask[i + 1];
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

            clientHpAES = new AES(clientHp);
            serverHpAES = new AES(serverHp);

            clientAead = new GaloisCounterMode(new AES(clientKey), 16);
            serverAead = new GaloisCounterMode(new AES(serverKey), 16);

            nonce = new byte[clientIv.Length];
            headerMask = new byte[16];
        }

        internal void ChangeReadEncryption(Crypto crypto, byte[] trafficSecret)
        {
            crypto.AEADFactory_QUIC(trafficSecret, out var newRead, out var newIv, out var newHpAes, out var newHpChaCha);

            if (endpoint == EndpointType.Server)
            {
                clientAead = newRead;
                clientIv = newIv;
                clientHpAES = newHpAes;
                clientHpChacha = newHpChaCha;
            }
            else
            {
                serverAead = newRead;
                serverIv = newIv;
                serverHpAES = newHpAes;
                serverHpChacha = newHpChaCha;
            }

            // todo what len of mask?
            nonce = new byte[newIv.Length];
            headerMask = new byte[16];
        }

        internal void ChangeWriteEncryption(Crypto crypto, byte[] trafficSecret)
        {
            crypto.AEADFactory_QUIC(trafficSecret, out var newWrite, out var newIv, out var newHpAes, out var newHpChaCha);

            if (endpoint == EndpointType.Server)
            {
                serverAead = newWrite;
                serverIv = newIv;
                serverHpAES = newHpAes;
                serverHpChacha = newHpChaCha;
            }
            else
            {
                clientAead = newWrite;
                clientIv = newIv;
                clientHpAES = newHpAes;
                clientHpChacha = newHpChaCha;
            }

            // todo what len of mask?
            nonce = new byte[newIv.Length];
            headerMask = new byte[16];
        }
    }
}