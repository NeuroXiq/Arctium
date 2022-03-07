using Arctium.Shared.Helpers.Binary;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Interfaces;
using System.IO;

namespace Arctium.Cryptography.HashFunctions.CRC
{
    public abstract class CRC<T> : IProcessBytes, IName
    {
        /// <summary>
        /// Plynomial used in CRC calculations
        /// </summary>
        public readonly T Polynomial;

        /// <summary>
        /// Indicates if all bits in input bytes are reversed. E.g
        /// if this value is true then following byte: 01000011 is reversed into 11000010 and then processed
        /// </summary>
        public readonly bool InputReflected;

        /// <summary>
        /// Indicates if all bits in result uint are reversed. Similar like InputReflected but 32 bit value is reversed/>
        /// </summary>
        public readonly bool ResultReflected;

        /// <summary>
        /// Initial value for 
        /// </summary>
        public readonly T InitialValue;

        /// <summary>
        /// Result will be xored with FinalXorValue right before return it
        /// </summary>
        public readonly T FinalXorValue;

        protected T currentValue;
        protected T[] lookupTable;

        public string Name { get; protected set; }

        public CRC(string name, 
            T polynomial,
            T initialValue,
            T finalXorValue,
            bool inputReflected,
            bool resultReflected)
        {
            Name = name;
            this.Polynomial = polynomial;
            this.InitialValue = initialValue;
            this.InputReflected = inputReflected;
            this.ResultReflected = resultReflected;
            this.FinalXorValue = finalXorValue;
            Reset();
        }



        public void Process(byte[] bytes)
        {
            Process(bytes, 0, bytes.Length);
        }

        public void Process(byte[] bytes, long offset, long length)
        {
            for (long i = offset; i < length + offset; i++)
            {
                byte byteToProcess = bytes[i];
                byte inputByte = InputReflected ? BinOps.BitReflect(byteToProcess) : byteToProcess;

                ProcessByte(inputByte);
            }
        }

        public void Process(Stream stream)
        {
            SimpleBufferForStream simpleBuffer = new SimpleBufferForStream();

            simpleBuffer.MediateAllBytesInto(stream, this);
        }

        public void Reset()
        {
            currentValue = InitialValue;
        }

        protected abstract void ProcessByte(byte b);

        public abstract T Result();
    }
}
