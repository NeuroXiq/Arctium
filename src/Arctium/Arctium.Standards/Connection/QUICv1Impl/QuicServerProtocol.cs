using Arctium.Shared.Helpers.Buffers;
using Arctium.Standards.Connection.QUICv1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Arctium.Standards.Connection.QUICv1Impl
{
    internal class QuicServerProtocol
    {
        private DgramIO dgramio;
        private ByteBuffer buffer;
        private byte[] readDgramBuf = new byte[16 * 1024];

        public QuicServerProtocol(DgramIO dgramio)
        {
            this.buffer = new ByteBuffer();
            this.dgramio = dgramio;
        }

        public async Task AcceptClientAsync()
        {
            // todo timeout somewhere (how long wait to receive data?)
            int datalen = 0;
            for (int i = 0; i < 50 && datalen == 0; i++)
            {
                datalen = await dgramio.ReadDgramAsync(readDgramBuf, 0);
                Thread.Sleep(100);
            }

            if (datalen == 0) throw new Exception("protocol error: timeout read");
            
            buffer.Append(readDgramBuf, 0, datalen);
        }

        public void WriteData()
        {
            
        }

        public void ReadData()
        {
            
        }

        private void LoadDgram()
        {
            
        }
    }
}
