using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Arctium.Shared.Helpers.Binary;
using Arctium.Shared.Helpers.Buffers;

namespace Arctium.Tests.Core
{
    public class RepeatStream : Stream
    {
        public override bool CanRead => throw new NotImplementedException();

        public override bool CanSeek => throw new NotImplementedException();

        public override bool CanWrite => throw new NotImplementedException();

        public override long Length => throw new NotImplementedException();

        public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public int RepeatStreamCursorPosition => cursor;
        public int RepeatStreamRepeatCount => repeatCount;

        byte[] bytesToRepeat;
        int remaining;
        int cursor;
        int toWriteOnNextCall;
        int maxWrite;
        int minWrite;
        int repeatCount;
        private Action<int> dataReadedCallback;

        public RepeatStream(byte[] bytesToRepeat, 
            int repeatCount,
            int minWrite,
            int maxWrite)
        {
            this.bytesToRepeat = new byte[bytesToRepeat.Length];
            this.remaining = this.bytesToRepeat.Length * repeatCount;
            this.cursor = 0;
            this.maxWrite = maxWrite;
            this.minWrite = minWrite;
            this.repeatCount = repeatCount;
            MemCpy.Copy(bytesToRepeat, this.bytesToRepeat);
        }

        public void SetDataReadedCallback(Action<int> callback)
        {
            this.dataReadedCallback = callback;
        }

        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (count < 1 || cursor == repeatCount - 1) return 0;

            int remainingBytes = repeatCount - cursor;

            int toWriteCount = count < toWriteOnNextCall ? count : toWriteOnNextCall;
            toWriteCount = toWriteCount > remainingBytes ? remainingBytes : toWriteCount;

            for (int i = 0; i < toWriteCount; i++)
            {
                buffer[offset + i] = bytesToRepeat[cursor % bytesToRepeat.Length];

                cursor++;
            }


            toWriteOnNextCall++;
            toWriteOnNextCall = toWriteOnNextCall > maxWrite ? minWrite : toWriteOnNextCall;



            dataReadedCallback?.Invoke(toWriteCount);

            return toWriteCount;

            int loadedToBuf = 0;

            if (remaining > 0)
            {
                if (cursor == 0 && count > bytesToRepeat.Length && remaining >= count)
                {
                    int fullBufRepeat = count / bytesToRepeat.Length;
                    
                    for (int i = 0; i < fullBufRepeat; i++)
                    {
                        MemCpy.Copy(bytesToRepeat, 0, buffer, offset, bytesToRepeat.Length);
                        offset += bytesToRepeat.Length;
                        remaining -= bytesToRepeat.Length;
                        loadedToBuf += bytesToRepeat.Length;
                    }

                    Console.WriteLine("{0:X8}", remaining);

                    return loadedToBuf;
                }

                int canRead = bytesToRepeat.Length - cursor;
                canRead = canRead > remaining ? remaining : canRead;
                MemCpy.Copy(bytesToRepeat, cursor, buffer, offset, canRead);
                cursor += canRead;
                loadedToBuf += canRead;

                if (cursor == bytesToRepeat.Length)
                {
                    cursor = 0;
                }

                remaining-=canRead;
            }

            return loadedToBuf;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }
    }
}
