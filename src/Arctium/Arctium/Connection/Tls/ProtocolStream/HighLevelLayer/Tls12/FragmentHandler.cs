using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12;

namespace Arctium.Connection.Tls.ProtocolStream.HighLevelLayer.Tls12
{
    abstract class FragmentHandler
    {
        public abstract void Handshake(FragmentData fragmentData);
        public abstract void ChangeCipherSpec(FragmentData fragmentData);
        public abstract void Alert(FragmentData fragmentData);
        public abstract void ApplicationData(FragmentData fragmentData); 
    }
}
