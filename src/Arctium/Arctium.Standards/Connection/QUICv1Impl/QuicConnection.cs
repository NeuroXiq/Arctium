using Arctium.Shared.Helpers.Buffers;
using Arctium.Standards.Connection.QUICv1Impl.Model;
using Arctium.Standards.RFC;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Standards.Connection.QUICv1Impl
{
    internal class QuicConnection
    {
        private QuicServerProtocol quicServer;
        private ByteBuffer packets = new ByteBuffer();
        private QuicCrypto crypto = new QuicCrypto();
        
        private byte[] tempDecryptedPkt = new byte[65535];

        public byte[] ServerConnectionId { get; set; }
        public byte[] ClientConnectionId { get; set; }

        bool isFirstPkg = true;

        public QuicConnection(QuicServerProtocol quicServer)
        {
            this.quicServer = quicServer;
        }

        internal void BufferPacket(byte[] buff, int offs, int packetLength)
        {
            int nextPkgOffs = packets.MallocAppend(packetLength);
            MemCpy.Copy(buff, offs, packets.Buffer, nextPkgOffs, packetLength);
        }

        public async Task AcceptClient()
        {
            await ProcessPackets();

            // Debugger.Break();
        }

        async Task ProcessPackets()
        {
            if (packets.DataLength == 0) await quicServer.LoadPacket();
            // MemCpy.Copy(testpacketprotected, 0, packets.Buffer, 0, testpacketprotected.Length);

            var lhp = QuicModelCoding.DecodeLHP(packets.Buffer, 0, true);
            crypto.SetupInitCrypto(lhp.DestConId);

            crypto.DecryptPacket(packets.Buffer, 0, tempDecryptedPkt, 0);
            lhp = QuicModelCoding.DecodeLHP(tempDecryptedPkt, 0, false);

            int i = 0;
            while (true)
            {
                if (i >= lhp.Payload.Length)
                {
                    Debugger.Break();
                }

                FrameType ft = (FrameType)lhp.Payload.Span[i];

                switch (ft)
                {
                    case FrameType.Padding: i++; continue;
                    case FrameType.Ping:
                        i++; continue;
                    
                    case FrameType.Crypto:
                        var cf = QuicModelCoding.DecodeFrame_Crypto(lhp.Payload, i);
                        i += cf.A_TotalLength;
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
                        
                    case FrameType.ConnectionCloseD:
                        
                    case FrameType.HandshakeDone:
                        
                    default: throw new Exception("unknown");
                        break;
                }

            }
        }

        public void ReadDataAsync()
        {

        }

        public void WriteDataAsync()
        {
            
        }

        internal void BufferPacket(byte[] drams, int v, object totalPacketLength)
        {
            throw new NotImplementedException();
        }
    }
}
