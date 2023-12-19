using Arctium.Cryptography.Ciphers.BlockCiphers;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Standards.Connection.QUICv1;
using Arctium.Standards.Connection.QUICv1Impl.Model;
using Arctium.Standards.Connection.Tls13;
using Arctium.Standards.Connection.Tls13Impl.Model;
using Arctium.Standards.Connection.Tls13Impl.Model.Extensions;
using Arctium.Standards.Connection.Tls13Impl.Protocol;
using Arctium.Standards.FileFormat.PEM;
using Arctium.Standards.PKCS8.v12;
using Arctium.Standards.RFC;
using Arctium.Standards.X509.X509Cert;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Standards.Connection.QUICv1Impl
{
    class QuicPNS
    {
        ByteBuffer actWait = new ByteBuffer();
        public QuicCrypto crypto;

        public uint PacketNumber = 0;
        public long LargestAck = -1;

        public QuicPNS()
        {
            PacketNumber = 1;
        }
    }

    class PacketSendBuffer
    {
        public int maxUdpDataLength = 1250;
        public byte[] Buffer;

        public PacketSendBuffer()
        {
            maxUdpDataLength = 1250;
            Buffer = new byte[1250];
        }
    }

    public enum EndpointType
    {
        Client,
        Server
    }

    internal class QuicConnection
    {
        private EndpointType endpoint;
        private QuicServerProtocol quicServer;
        private ByteBuffer packets = new ByteBuffer();
        private QuicStream cryptoFramesStream = new QuicStream();

        private byte[] tempDecryptedPkt = new byte[65535];
        private ByteBuffer toSendPacketHeader = new ByteBuffer();
        private ByteBuffer toSendPacketFrames = new ByteBuffer();
        private byte[] encryptedToSend = new byte[65535];

        private QuicPNS initialPns;

        public byte[] ServerConnectionId { get; set; }
        public byte[] ClientConnectionId { get; set; }

        private byte[] onSendingSrcConnId { get { return endpoint == EndpointType.Client ? ServerConnectionId : ClientConnectionId; } }
        private byte[] onSendingDestConnId { get { return endpoint == EndpointType.Client ? ClientConnectionId : ServerConnectionId; } }

        bool isFirstPkg = true;
        int maxUpdDataLength = 1250;

        private byte[] originalDestinationConnectionId;

        private Tls13Server tlsServer;

        public QuicConnection(QuicServerProtocol quicServer, EndpointType endpoint)
        {
            this.endpoint = endpoint;
            this.quicServer = quicServer;
            this.initialPns = new QuicPNS();
            this.initialPns.crypto = new QuicCrypto(endpoint);

            var certificateWithPrivateKey = QuicTests.QuicTests.CERT_WITH_KEY_cert_rsaencrypt_2048_sha256_1;
            var serverContext = Tls13ServerContext.QuicIntegrationDefault(new[] { certificateWithPrivateKey });
            serverContext.Config.ConfigueExtensionSupportedGroups(new Tls13.Extensions.ExtensionServerConfigSupportedGroups(new NamedGroup[] { NamedGroup.X25519 }));
            this.tlsServer = new Tls13Server(serverContext);
        }

        internal void BufferPacket(byte[] buff, int offs, int packetLength)
        {
            int nextPkgOffs = packets.MallocAppend(packetLength);
            MemCpy.Copy(buff, offs, packets.Buffer, nextPkgOffs, packetLength);
        }

        public async Task AcceptClient()
        {
            await ProcessPackets();
            var quicStream = new QuicIntegrationTlsNetworkStream(this);
            this.tlsServer.Accept(quicStream);
        }

        bool isinit = true;

        async Task ProcessPackets()
        {
            if (packets.DataLength == 0) await quicServer.LoadPacket();
            // MemCpy.Copy(testpacketprotected, 0, packets.Buffer, 0, testpacketprotected.Length);

            LongHeaderPacket lhp;

            if (isinit)
            {
                isinit = false;
                lhp = QuicModelCoding.DecodeLHP(packets.Buffer, 0, true);
                this.initialPns.crypto.SetupInitCrypto(lhp.DestConId);
                this.originalDestinationConnectionId = lhp.DestConId.ToArray();

                this.ServerConnectionId = lhp.DestConId.ToArray();

                if (lhp.SrcConId.Length == 0)
                {
                    this.ClientConnectionId = lhp.DestConId.ToArray();
                }
            }

            this.initialPns.crypto.DecryptPacket(packets.Buffer, 0, tempDecryptedPkt, 0);
            lhp = QuicModelCoding.DecodeLHP(tempDecryptedPkt, 0, false);
            
            packets.TrimStart(lhp.A_TotalPacketLength);

            byte[] p = tempDecryptedPkt;

            int i = lhp.A_HeaderLength;
            while (i < lhp.A_TotalPacketLength)
            {
                FrameType ft = (FrameType)p[i];

                switch (ft)
                {
                    case FrameType.Padding: i++; continue;
                    case FrameType.Ping:
                        i++; continue;
                    
                    case FrameType.Crypto:
                        var cf = QuicModelCoding.DecodeFrame_Crypto(p, i);
                        cryptoFramesStream.RecvStreamFrame(cf);
                        i += cf.A_TotalLength;
                        // MemCpy.Copy(cf.Data.Span, 0, p, (int)cf.Offset, (int)cf.Length);
                        break;
                    case FrameType.Ack2:
                        
                    case FrameType.Ack3:
                        
                    case FrameType.ResetStream:
                        
                    case FrameType.StopSending:
                        
                    case FrameType.NewToken:
                        
                    case FrameType.Stream:
                        
                    case FrameType.MaxData:
                        
                    case FrameType.MaxStreamData:
                        
                    case FrameType.MaxStreams2:
                        
                    case FrameType.MaxStreams3:
                        
                    case FrameType.DataBlocked:
                        
                    case FrameType.StreamDataBlocked:
                        
                    case FrameType.StreamsBlocked6:
                        
                    case FrameType.StreamsBlocked7:
                        
                    case FrameType.NewConnectionId:
                        
                    case FrameType.RetireConnectionId:
                        
                    case FrameType.PathChallenge:
                        
                    case FrameType.PathResponse:
                        
                    case FrameType.ConnectionCloseC:
                        var closec = QuicModelCoding.DecodeFrame_Close(p, i);
                        throw new QuicException("connection close");
                        break;
                        
                    case FrameType.ConnectionCloseD:
                        
                    case FrameType.HandshakeDone:
                        
                    default: throw new Exception("unknown");
                        break;
                }

            }

            //var md = new ModelDeserialization(new Validate(new Validate.ValidationErrorHandler(null)));
            //var d = md.Deserialize<ClientHello>(cframes, 0);

            // Debugger.Break();
        }

        public void ReadDataAsync(byte[] outputBuffer, long offset, long length)
        {

        }

        public void WriteDataAsync(byte[] buffer, long offset, long length)
        {

        }

        Memory<byte>[] Split(byte[] buffer, int offset, int length, int chunkLength)
        {
            int count = (length + chunkLength - 1) / chunkLength;
            Memory<byte>[] r = new Memory<byte>[count];
            
            // full length chunks
            for (int i = 0; i < count; i++)
            {
                int nextOffs = (i * chunkLength) + offset;
                int windowLen = length >= chunkLength ? chunkLength : length;
                
                r[i] = new Memory<byte>(buffer, nextOffs, chunkLength);
                length -= windowLen;
            }

            // last chunk (maybe not full length)
            // int rem = length - (count * chunkLength);
            
            // r[count - 1] = new Memory<byte>(buffer, offset + ((count - 1) * chunkLength), rem);

            return r;
        }

        async Task SendPacket(QuicPNS pns)
        {
            throw new NotImplementedException();
        }

        async Task WriteInitialPacket(byte[] buffer, int offset, int length)
        {
            // todo what lenght to split?
            int maxFrameDataLen = 1024;
            var frames = Split(buffer, offset, length, maxFrameDataLen);
            int stoffs = 0;

            foreach (var chunk in frames)
            {
                var f = new CryptoFrame
                {
                    Data = chunk,
                    Length = (ulong)chunk.Length,
                    Offset = (ulong)stoffs
                };

                stoffs += chunk.Length;

                // clear (so will by default have padding packets)
                MemOps.MemsetZero(toSendPacketFrames.Buffer);
                QuicModelCoding.Encode_CryptoFrame(toSendPacketFrames, f);

                // length including padding
                // throw new Exception("implement padding");
                // int lengthWithPadding = toSendPacketFrames.


                initialPns.PacketNumber++;
                var p = InitialPacket.Create(
                    onSendingDestConnId,
                    onSendingSrcConnId,
                    new Memory<byte>(),
                    initialPns.PacketNumber,
                    initialPns.LargestAck,
                    (ulong)toSendPacketFrames.DataLength);

                QuicModelCoding.Encode_InitialPacketSkipPayload(toSendPacketHeader, p);

                int toSendLen = initialPns.crypto.EncryptPacket(
                toSendPacketHeader.Buffer,
                0,
                toSendPacketHeader.DataLength,
                toSendPacketFrames.Buffer,
                0,
                toSendPacketFrames.DataLength,
                encryptedToSend,
                0);

                await this.quicServer.WritePacket(encryptedToSend, 0, toSendLen);
            }
        }

        #region TLS13 Integration

        internal int TlsReadBytes(byte[] buffer, int offset, int length)
        {
            if (length == 0) return 0;

            while (!cryptoFramesStream.HasData)
            {
                ProcessPackets().Wait();
            }

            checked
            {
                return cryptoFramesStream.Read(buffer, offset, length);
            }
        }

        internal void TlsWriteBytes(byte[] buffer, long offset, int length)
        {
            checked
            {
                (WriteInitialPacket(buffer, (int)offset, length)).Wait();
            }
        }

        internal QuicTransportParametersExtension GetQuicTransportParametersServer(QuicTransportParametersExtension clientHelloQuicTransportParams)
        {
            // only by server
            QuicTransportParametersExtension.OriginalDestinationConnectionId e1 = new QuicTransportParametersExtension.OriginalDestinationConnectionId(this.originalDestinationConnectionId);
            
            QuicTransportParametersExtension.MaxIdleTimeout maxIdle = new QuicTransportParametersExtension.MaxIdleTimeout(0);
            QuicTransportParametersExtension.MaxUdpPayloadSize maxUdp = new QuicTransportParametersExtension.MaxUdpPayloadSize(65527);
            QuicTransportParametersExtension.InitialMaxData imd = new QuicTransportParametersExtension.InitialMaxData(1024 * 1024 * 50);
            ulong maxdata = 1024 * 1024 * 50;
            QuicTransportParametersExtension.InitialMaxStreamDataBidiLocal imsdbl = new QuicTransportParametersExtension.InitialMaxStreamDataBidiLocal(maxdata);
            QuicTransportParametersExtension.InitialMaxStreamDataBidiRemote imsdbr = new QuicTransportParametersExtension.InitialMaxStreamDataBidiRemote(maxdata);
            QuicTransportParametersExtension.InitialMaxStreamDataUni imsdu = new QuicTransportParametersExtension.InitialMaxStreamDataUni(maxdata);
            QuicTransportParametersExtension.InitialSourceConnectionId isci = new QuicTransportParametersExtension.InitialSourceConnectionId(this.ServerConnectionId);

            var tparms = new QuicTransportParametersExtension.TransportParameter[]
            {
                e1,
                maxIdle,
                maxUdp,
                imd,
                imsdbl,
                imsdbr,
                imsdu,
                isci
            };

            return new QuicTransportParametersExtension(tparms);

            // retry source connection id??

            // absent or zero
            //QuicTransportParametersExtension.InitialMaxStreamsBidi imsb = new QuicTransportParametersExtension.InitialMaxStreamsBidi
            //InitialMaxStreamsUni

            // can absent
            //ack_delay_exponent
            //max_ack_delay
            //active_connection_id_limit

            // included if endpoint not support migration
            //disable_active_migration

            // only by server if change address
            //preferred_address
        }

        #endregion
    }

    class QuicIntegrationTlsNetworkStream : Stream
    {
        public override bool CanRead => throw new NotImplementedException();

        public override bool CanSeek => throw new NotImplementedException();

        public override bool CanWrite => throw new NotImplementedException();

        public override long Length => throw new NotImplementedException();

        public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        QuicConnection connection;

        public QuicIntegrationTlsNetworkStream(QuicConnection connection)
        {
            this.connection = connection;
        }

        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => connection.TlsReadBytes(buffer, offset, count);
        public override void Write(byte[] buffer, int offset, int count) => connection.TlsWriteBytes(buffer, offset, count);

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        internal void ChangeReadEncryption(AEAD newRead, byte[] newIv)
        {
            throw new NotImplementedException();
        }

        internal void ChangeWriteEncryption(AEAD newRead, byte[] newIv)
        {
            throw new NotImplementedException();
        }

        internal QuicTransportParametersExtension GetQuicTransportParametersServer(QuicTransportParametersExtension clientHelloQuicTransportParams)
        {
            return connection.GetQuicTransportParametersServer(clientHelloQuicTransportParams);
        }
    }
}

namespace QuicTests
{
    public class QuicTests
    {
        public static readonly X509CertWithKey CERT_WITH_KEY_cert_rsaencrypt_2048_sha256_1;
        public static readonly X509CertWithKey CERT_WITH_KEY_cert_secp256r1_sha256_1;
        public static readonly X509CertWithKey CERT_WITH_KEY_cert_secp384r1_sha384_1;


        static QuicTests()
        {
            CERT_WITH_KEY_cert_rsaencrypt_2048_sha256_1 = ParseCert(RAWPEM_CERT_cert_resa_2048_sha256_1, RAWPEM_KEY_cert_resa_2048_sha256_1);
            CERT_WITH_KEY_cert_secp256r1_sha256_1 = ParseCert(RAWPEM_CERT_cert_secp256r1_sha256_1, RAWPEM_KEY_cert_secp256r1_sha256_1);
            CERT_WITH_KEY_cert_secp384r1_sha384_1 = ParseCert(RAWPEM_CERT_cert_secp384r1_sha384_1, RAWPEM_KEY_cert_secp384r1_sha384_1);
        }

        //public static NetworkStream NetworkStreamToExampleServer()
        //{
        //    // socket to some server

        //    var ip = Dns.GetHostAddresses("www.github.com")[0];

        //    Socket socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        //    socket.Connect(new IPEndPoint(ip, 443));

        //    return new NetworkStream(socket);
        //}

        static X509CertWithKey ParseCert(string cert, string key)
        {
            X509CertificateDeserializer deserializer = new X509CertificateDeserializer();
            var x509 = deserializer.FromPem(PemFile.FromString(cert));
            var keyparsed = PKCS8v12.FromPem(PemFile.FromString(key));

            return new X509CertWithKey(x509, keyparsed.PrivateKey);
        }

        // generated on https://certificatetools.com/

        static readonly string RAWPEM_KEY_cert_secp384r1_sha384_1 =
        @"
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCoZPC9kmR5sF0YWEFx
kilxhIq89K9wIpZ5QfGdkrZkyceWjSsi7JlvfJE0qb0CSmGhZANiAASyjY2vHLay
IUSup5iVekf8PFFrI6sDTOT4/hsy6bdnY8626xKWuigg2Y0ZC53hGoMEe/ZKigTr
sRnrAsmrQivaYK7AbvbFk7B2k8VB/x2A9HwIZxvLJ0y6D3idIC2CBjU=
-----END PRIVATE KEY-----

";

        static readonly string RAWPEM_CERT_cert_secp384r1_sha384_1 =
        @"
-----BEGIN CERTIFICATE-----
MIICkzCCAhmgAwIBAgIUC7Xzr07p82HXnjQvS1LzKDHRQuEwCgYIKoZIzj0EAwMw
XTElMCMGA1UEAwwcd3d3LmFyY2l0dW0tdGVzdGNlcnQtZWNjLmNvbTELMAkGA1UE
BhMCUEwxFjAUBgNVBAgMDUxlc3NlciBQb2xhbmQxDzANBgNVBAcMBktyYWtvdzAe
Fw0yMjEwMjIwOTU4MTZaFw0yNTEwMjEwOTU4MTZaMF0xJTAjBgNVBAMMHHd3dy5h
cmNpdHVtLXRlc3RjZXJ0LWVjYy5jb20xCzAJBgNVBAYTAlBMMRYwFAYDVQQIDA1M
ZXNzZXIgUG9sYW5kMQ8wDQYDVQQHDAZLcmFrb3cwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAASyjY2vHLayIUSup5iVekf8PFFrI6sDTOT4/hsy6bdnY8626xKWuigg2Y0Z
C53hGoMEe/ZKigTrsRnrAsmrQivaYK7AbvbFk7B2k8VB/x2A9HwIZxvLJ0y6D3id
IC2CBjWjgZkwgZYwHQYDVR0OBBYEFN1znynYHDdNrtnBYiQgbPyP1Q2AMB8GA1Ud
IwQYMBaAFN1znynYHDdNrtnBYiQgbPyP1Q2AMA4GA1UdDwEB/wQEAwIFoDAgBgNV
HSUBAf8EFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwIgYDVR0RBBswGYIXd3d3LmFj
dGl1bS10ZXN0Y2VydC5jb20wCgYIKoZIzj0EAwMDaAAwZQIwEOGR7PnQp7y/Uo1+
nMbvlHvy4asKoTizZl3F1uUwisb/BxskpGVWyLg8vIydLR3yAjEA2mH7lCLcpccK
ld/NnQnM+QqZOY2D+Dfo4URu4YFTbIpArW5xNawf6SalHoyTJpe/
-----END CERTIFICATE-----

";


        static readonly string RAWPEM_KEY_cert_secp256r1_sha256_1 =
        @"
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/JxWWIEVZWW7Alci
82pe2SzC22G6w7KuUwCj6XzeaMehRANCAASASBvcKJEApoRFUk2drksYvmybQ+B8
G5BfD/+/rqOneClSvT8KP3D362FjDF6ORAzLPJUDlqvIi9iMexAN+SSh
-----END PRIVATE KEY-----

";

        static readonly string RAWPEM_CERT_cert_secp256r1_sha256_1 =
       @"
-----BEGIN CERTIFICATE-----
MIICVTCCAfygAwIBAgIUbd+/gaeBWu0a4fZD4Rrg80GoSBkwCgYIKoZIzj0EAwIw
XTElMCMGA1UEAwwcd3d3LmFyY2l0dW0tdGVzdGNlcnQtZWNjLmNvbTELMAkGA1UE
BhMCUEwxFjAUBgNVBAgMDUxlc3NlciBQb2xhbmQxDzANBgNVBAcMBktyYWtvdzAe
Fw0yMjEwMjIwOTQ2NDhaFw0yNTEwMjEwOTQ2NDhaMF0xJTAjBgNVBAMMHHd3dy5h
cmNpdHVtLXRlc3RjZXJ0LWVjYy5jb20xCzAJBgNVBAYTAlBMMRYwFAYDVQQIDA1M
ZXNzZXIgUG9sYW5kMQ8wDQYDVQQHDAZLcmFrb3cwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAASASBvcKJEApoRFUk2drksYvmybQ+B8G5BfD/+/rqOneClSvT8KP3D3
62FjDF6ORAzLPJUDlqvIi9iMexAN+SSho4GZMIGWMB0GA1UdDgQWBBQNWKAhNWNu
17Q8m5PBoQCmEHKu4zAfBgNVHSMEGDAWgBQNWKAhNWNu17Q8m5PBoQCmEHKu4zAO
BgNVHQ8BAf8EBAMCBaAwIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MCIGA1UdEQQbMBmCF3d3dy5hY3RpdW0tdGVzdGNlcnQuY29tMAoGCCqGSM49BAMC
A0cAMEQCIG9NhayGUBGYIvUltkXP5//ZBJjXa4vplM9YsEo6ByH6AiBRcUIC5vHG
lBnq8WiChGv74UD6N5Vw+FwXJzMMAhJOzA==
-----END CERTIFICATE-----

";

        static readonly string RAWPEM_KEY_cert_resa_2048_sha256_1 =
        @"
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDeiu3ulQ8sOPis
+BREJ+3zWdUFq/RJheNZXKWBRzN+S19Nr2E9iinG/jNG1/6Cm1VmMrYH7rPEj/D7
1qWygZ+qbF0HSZuogfPvwuB+2y6ssd4HzhNDHb6UXuqe0q/JYMNU9YppXFajWBKb
CplDFxne/dcAqMl9P1ILB7otQYcxgVnlfCeME0v0Ja+hUyoDKRBBYwqSgovJ7BNc
115Uybpv2fbIs46KUEf0KJcOgeg4XFmIxudAcIM6sze7yERl1/O4g8m8dHJP8m/+
e4Wkd2WAFNZRHezeTzYKosaZEVVhe77/b68shKgdZzR9HD/QpTx3Wtjg/MKx/l0+
QIkO84KtAgMBAAECggEBANuqoyWneOyb58tErSyBhX16JK2OiHmycTGaI7wyPf/i
Ala6UO/f21ETRiYdupnNHkTctZWq50OVGbhcrf4/uQ0OHd29qKpybAk0gUh2reHF
SHbH0XekeqQV9N2E9gN/QhAwtsk9Xj+qBeOIWLRCr0TPp1R9RzYcNK2ymPFnBz2y
q3WBkY7q6j4Aj0E+UvjxvKxRXPd7LEymp8yXeHJYPt2qCYQvqWrVvSwxC+qf4foY
gyu4mTZM08LJRidd30sVarGCB6HSPxxRJsbJfUFs/Yi3dKCx4Ykf6Aivd48/Y5bX
2YGRi65ygoKKL4HW042RHfBPnfVa5GN9NdErerh3NgECgYEA8q8YpU4m3X8FnWzc
ra+5cYcg2VZ7aOvJ2lYyDVTkRvDsX/8wvsZVPItXP9aFh9uoMC6IXj26euV2x4e/
BLlJMC+AtvYabxiNFy855/wCIPDYOrFRs9Li1ZStTob8ZP4ZUxZrkUyPPmP2bTYv
Zs73L98KITAbfl1xFLOCs0mp5W0CgYEA6sDqRINxs7cVPSaVCRFGRHPfjfuwYF+R
AKsnstVkS3a5k7kpm15T9TuZsTW1DAoQk3zAzpW724WJBFTp31Myv61WZPwuBOZl
Z+k5Ka5GPjKBKtj0mkGsNkHl7HP5ftv5ftAQm+h3Vh+dvdGk7/kvTj3UIbQ/jCeG
5Bx4H4ECCkECgYEAk/FKBPvvlXep5J5IqVlGo37M97FQ6lVTaFbDjH0D7HtSnfLj
tGkT7STEu5X7MScnELhNSaY32FOqZVjLigWqKEXNIbxFwRQmbsvLcTCf25T3PFB8
jjMxNSK9w/FmS+rbZVt1l84kRNSLlWhC3VmuNvCxLCo3mIE+PnBwbPurJsECgYA9
NY/fzWYYNeSTzTuO4bIwpwXjP3z9o+1q/zWaq4k7I/m/SshOeonpp2CrlBVgzj8E
NcMQGnqhAnB3cKyKTmctE0Uzj41wOaK3NVhyRb6K+SA0y9z7W6RLgWMyBAtJyJGF
PzsVa8ex7Qx0MfWPnKl4/SYSo6zuHmBNmh64GCswAQKBgQDwJTmpA5QH11R7JxHq
hOX+JEp+lVJ21q1/gaOziJ9wV0uahPDS1LtupxEQmPEQNaWy98s+vywGd9AgGzgT
/iABTiuAOwzBrnbqyg2NZ2zpggG406VUNzv15t4uruPuCAMaL/Lk5yZkC0170T+x
IqYFh39n0+zv63V5mODJJDdj3g==
-----END PRIVATE KEY-----

";

        static readonly string RAWPEM_CERT_cert_resa_2048_sha256_1 =
        @"
-----BEGIN CERTIFICATE-----
MIID4jCCAsqgAwIBAgIUYYet3/tggZHo5LuPTsOWeDt8M3owDQYJKoZIhvcNAQEL
BQAwXTElMCMGA1UEAwwcd3d3LmFyY2l0dW0tdGVzdGNlcnQtZWNjLmNvbTELMAkG
A1UEBhMCUEwxFjAUBgNVBAgMDUxlc3NlciBQb2xhbmQxDzANBgNVBAcMBktyYWtv
dzAeFw0yMjEwMjIxMDAxNDNaFw0yNTEwMjExMDAxNDNaMF0xJTAjBgNVBAMMHHd3
dy5hcmNpdHVtLXRlc3RjZXJ0LWVjYy5jb20xCzAJBgNVBAYTAlBMMRYwFAYDVQQI
DA1MZXNzZXIgUG9sYW5kMQ8wDQYDVQQHDAZLcmFrb3cwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDeiu3ulQ8sOPis+BREJ+3zWdUFq/RJheNZXKWBRzN+
S19Nr2E9iinG/jNG1/6Cm1VmMrYH7rPEj/D71qWygZ+qbF0HSZuogfPvwuB+2y6s
sd4HzhNDHb6UXuqe0q/JYMNU9YppXFajWBKbCplDFxne/dcAqMl9P1ILB7otQYcx
gVnlfCeME0v0Ja+hUyoDKRBBYwqSgovJ7BNc115Uybpv2fbIs46KUEf0KJcOgeg4
XFmIxudAcIM6sze7yERl1/O4g8m8dHJP8m/+e4Wkd2WAFNZRHezeTzYKosaZEVVh
e77/b68shKgdZzR9HD/QpTx3Wtjg/MKx/l0+QIkO84KtAgMBAAGjgZkwgZYwHQYD
VR0OBBYEFPYEGkRXuOVRGQ6ZKTPek0pvJMudMB8GA1UdIwQYMBaAFPYEGkRXuOVR
GQ6ZKTPek0pvJMudMA4GA1UdDwEB/wQEAwIFoDAgBgNVHSUBAf8EFjAUBggrBgEF
BQcDAQYIKwYBBQUHAwIwIgYDVR0RBBswGYIXd3d3LmFjdGl1bS10ZXN0Y2VydC5j
b20wDQYJKoZIhvcNAQELBQADggEBADlS3K7PgHzun3KQ8wgQ8gDi37hqtgjYJGF6
Sah4d/R3jHbq4y/QGwsZYayCT9b9/d/0/cuveYFhwLsLvD8b3pXMlrtamh6QeH8K
+orK5a7c5SEwqfx/LP4x5WjYZhq2WvGXY+rRMscFbaYh+UMv8dPlm1zFvRiPRm2k
uAKEkIHDuJNBBERSmg3Qso3ATCVGlyjHb7jkzKXJrdCBjbe0iaswi7yr8j0UuiHm
f2f6ATLaK0T/ZIR/ZIn4U3PpgsRnqEqjLRzgHSjoqx/yr/Nb5E7sotGFsoczmbQz
WMUpP3z6UnjDRAsu+Yrfxe09A8EqHes2qN9wt5XkfqQY0fMIFiI=
-----END CERTIFICATE-----

";
    }
}