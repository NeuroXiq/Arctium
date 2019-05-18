using System;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Connection.Tls.Operator.Tls12Operator
{
    class HandshakeHandler : FragmentHandler
    {
        

        FragmentReader reader;

        public HandshakeHandler(FragmentReader reader)
        {
            reader.ChangeHandler(this);
        }

        public override void Alert(FragmentData fragmentData)
        {
            throw new Exception("alert in handhskae");
        }

        public override void ApplicationData(FragmentData fragmentData)
        {
            throw new Exception("appdata in handshake");
        }

        public override void ChangeCipherSpec(FragmentData fragmentData)
        {
            throw new Exception("ccs in handshake");
        }

        public override void Handshake(FragmentData fragmentData)
        {
            
        }

        public Handshake Read()
        {
            return null;
        }
    }
}
