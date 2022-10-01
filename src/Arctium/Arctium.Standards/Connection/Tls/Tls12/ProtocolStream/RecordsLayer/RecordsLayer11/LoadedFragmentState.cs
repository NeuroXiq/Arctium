using Arctium.Standards.Connection.Tls.Protocol.RecordProtocol;

namespace Arctium.Standards.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer11
{
    class LoadedFragmentState
    {
        public RecordLayer11.LoadedFragment FragmentInfo;
        public bool IsLoaded;
        public byte[] DecryptedContentBuffer;

        private LoadedFragmentState() { }


        public void ResetToUnloaded()
        {
            IsLoaded = false;
            FragmentInfo = new RecordLayer11.LoadedFragment();
            FragmentInfo.Length = -1;
            FragmentInfo.ContentType = ContentType.Alert;
            DecryptedContentBuffer = null;
        }

        public void SetAsLoaded(byte[] buffer, int length, ContentType type)
        {
            IsLoaded = true;
            FragmentInfo.ContentType = type;
            FragmentInfo.Length = length;
            DecryptedContentBuffer = buffer;
        }

        public static LoadedFragmentState InitializeUnloaded()
        {
            LoadedFragmentState state = new LoadedFragmentState();
            
            state.ResetToUnloaded();

            return state;
        }
    }
}
