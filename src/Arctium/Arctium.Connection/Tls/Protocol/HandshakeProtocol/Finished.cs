namespace Arctium.Connection.Tls.Protocol.HandshakeProtocol
{
    class Finished : Handshake
    {
        public byte[] VerifyData;

        public Finished(byte[] verifyData)
        {
            MsgType = HandshakeType.Finished;
            VerifyData = verifyData;
        }
    }
}
