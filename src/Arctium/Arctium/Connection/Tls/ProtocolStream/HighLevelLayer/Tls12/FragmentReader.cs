using Arctium.Connection.Tls.Protocol.RecordProtocol;
using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12;
using System;

namespace Arctium.Connection.Tls.ProtocolStream.HighLevelLayer.Tls12
{
    class FragmentReader
    {
        FragmentHandler handler;
        RecordLayer12 recordLayer;

        public FragmentReader(RecordLayer12 recordLayer, FragmentHandler initHandler)
        {
            handler = initHandler;
            this.recordLayer = recordLayer;
        }

        public void ChangeHandler(FragmentHandler handler)
        {
            this.handler = handler;
        }

        public void Read()
        {
            ContentType type;
            FragmentData data = recordLayer.LoadFragment(out type);

            switch (type)
            {
                case ContentType.ChangeCipherSpec:
                    handler.ChangeCipherSpec(data);
                    break;
                case ContentType.Alert:
                    handler.Alert(data);
                    break;
                case ContentType.Handshake:
                    handler.Handshake(data);
                    break;
                case ContentType.ApplicationData:
                    handler.ApplicationData(data);
                    break;
                default: throw new Exception("Internal error, unrecognized type in FragmentReader");
            }
        }
    }
}
