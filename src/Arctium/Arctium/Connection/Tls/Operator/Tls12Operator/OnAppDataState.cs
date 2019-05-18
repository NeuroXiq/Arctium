using Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12;

namespace Arctium.Connection.Tls.Operator.Tls12Operator
{
    class OnAppDataState
    {
        RecordLayer12 recordLayer;

        public OnAppDataState(RecordLayer12 recordLayer)
        {
            this.recordLayer = recordLayer;
        }
    }
}
