using Arctium.Protocol.DNS.Model;
using Arctium.Protocol.DNS.Protocol;
using Arctium.Shared;
using System.Net;
using System.Net.Sockets;

namespace Arctium.Protocol.DNS
{
    public class DnsClientMessageIO_Rfc1035Classic : IDnsClientMessageIO
    {
        public readonly int UdpSocketRecvTimeoutMs;

        public readonly int TcpSocketRecvTimeoutMs;
        
        public readonly bool ReplyTcpWhenTruncated;

        public DnsClientMessageIO_Rfc1035Classic(
            int udpSocketRecvTimeoutMs,
            int tcpSocketRecvTimeoutMs,
            bool replyTcpWhenTruncated)
        {
            UdpSocketRecvTimeoutMs = udpSocketRecvTimeoutMs;
            TcpSocketRecvTimeoutMs = tcpSocketRecvTimeoutMs;
            ReplyTcpWhenTruncated = replyTcpWhenTruncated;
        }

        public async Task<Message> QueryServerAsync(DnsClientMessageIOArg arg)
        {
            var clientMessage = arg.Message;
            var ipAddress = arg.IpAddress;
            byte[] receiveBuffer;
            SocketReceiveFromResult sresult;
            IPEndPoint endpoint = null;
            Message serverMessage = null, result;
            DnsSerialize serialize = new DnsSerialize();
            ByteBuffer bbuf = new ByteBuffer();

            serialize.EncodeClassic(clientMessage, bbuf);

            if (bbuf.Length <= DnsConsts.UdpSizeLimit)
            {
                receiveBuffer = new byte[DnsConsts.UdpSizeLimit];
                endpoint = new IPEndPoint(ipAddress, DnsConsts.DefaultServerDnsPort);
                using var timeout = new CancellationTokenSource(UdpSocketRecvTimeoutMs);

                using (Socket socket = new Socket(ipAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp))
                {
                    await socket.SendToAsync(new ArraySegment<byte>(bbuf.Buffer, 0, bbuf.Length), endpoint);
                    sresult = await socket.ReceiveFromAsync(receiveBuffer, endpoint, timeout.Token);
                }

                result = serialize.Decode(new BytesCursor(receiveBuffer, 0, sresult.ReceivedBytes));
                serverMessage = result;

                if (serverMessage.Header.Id != clientMessage.Header.Id)
                    throw new DnsException(DnsProtocolError.ClientError, "server header id reply does not match client header ID");
            }

            if (serverMessage == null || (ReplyTcpWhenTruncated && serverMessage?.Header.TC == true))
            {
                using var timeout = new CancellationTokenSource(UdpSocketRecvTimeoutMs);

                throw new NotImplementedException();

                serverMessage = null; //todo
            }

            if (serverMessage.Header.Id != clientMessage.Header.Id)
                throw new DnsException(DnsProtocolError.ClientError, "server header id reply does not match client header ID");

            return serverMessage;
        }
    }
}
