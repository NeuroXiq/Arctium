using Arctium.Cryptography.ASN1.ObjectSyntax.Types;
using Arctium.Cryptography.ASN1.Serialization.Exceptions;
using System;
using System.Collections.Generic;

namespace Arctium.Cryptography.ASN1.Serialization.X690.DER
{
    // constructors stack is a recursion but is accomplished by this stack

    public class DerDeserializer
    {
        BufferFrame bufferFrame;
        byte[] buffer;

        Stack<X690DecodedNode> constructorsStack;

        public DerDeserializer(byte[] buffer)
        {
            constructorsStack = new Stack<X690DecodedNode>();
            this.buffer = buffer;
        }

        public X690DecodedNode Deserialize()
        {
            bufferFrame = new BufferFrame(buffer);
            bufferFrame.SeekFromStart(0);
            X690DecodedNode rootDecodedNode = new X690DecodedNode();
            rootDecodedNode.ContentLength = buffer.Length;
            rootDecodedNode.ConstructedContent = new List<X690DecodedNode>();

            constructorsStack.Push(rootDecodedNode);

            //TODO Config 
            // config

            CodingFrame codingFrame;

            bool continueDecoding = true;

            while (continueDecoding)
            {
                long frameShift = 0;

                if (ConstructorEndOfData())
                {
                    //check end of data


                    if (constructorsStack.Count == 1) break;

                    int shiftLength = PopCurrentConstructor();

                    if (shiftLength > 0)
                    {
                        bufferFrame.SeekFromCurrentPosition(shiftLength);
                        bufferFrame.Update();
                    }

                    continueDecoding = constructorsStack.Count > 1;
                    continue;
                }

                bufferFrame.Update();
                codingFrame = bufferFrame.CodingFrame;
                if (!codingFrame.ContentLength.IsDefinite) throw new NotSupportedException("Internal not supported -> todo, indefinite");

                if (codingFrame.PC == PCType.Primitive)
                {
                    // decode primitive
                    // push decoded value to current constructor on the stack
                    // move frame right

                    long contentLength = codingFrame.ContentLength.Length;

                    X690DecodedNode decodedNode = new X690DecodedNode();
                    decodedNode.Frame = codingFrame;
                    decodedNode.FrameOffset = bufferFrame.Offset;
                    decodedNode.ContentLength = contentLength;
                    decodedNode.DataBuffer = buffer;

                    AddToCurrentConstrucor(decodedNode);

                    frameShift = contentLength + codingFrame.FrameLength;

                    // in shift include 2 null bytes of the content (if present)
                    if (!codingFrame.ContentLength.IsDefinite) frameShift += 2;
                }
                else
                {
                    // create new constructed type
                    // add this type to constructots stack
                    // move frame right
                    // this constructor is from now 'current' constructor until 'pop'

                    PushNewConstructor();

                    frameShift = codingFrame.FrameLength;
                }

                bufferFrame.SeekFromCurrentPosition(frameShift);
            }

            // TODO ASN1/DER/Deserializer Implement metadata (what was parsed etc.)
            
            return rootDecodedNode;
        }

        private int PopCurrentConstructor()
        {
            X690DecodedNode constructor= constructorsStack.Peek();
            var ctor = constructorsStack.Pop();
            constructorsStack.Peek().AppendConstructorContent(constructor);
            if (constructor.Frame.ContentLength.IsDefinite)
            {
                return 0;
            }
            else
            {
                // shift after 2 end-of-content bytes, indefinite form
                return 2;
            }
        }

        private void PushNewConstructor()
        {
            CodingFrame codingFrame = bufferFrame.CodingFrame;

            //IConstructorDecoder constructor = constructorDecoders.Create(codingFrame.Tag, codingFrame);

            X690DecodedNode constructor = new X690DecodedNode();
            constructor.ConstructedContent = new List<X690DecodedNode>();
            constructor.Frame = codingFrame;
            constructor.ContentLength = codingFrame.ContentLength.Length;
            constructor.FrameOffset = bufferFrame.Offset;
            constructor.DataBuffer = buffer;

            constructorsStack.Push(constructor);
        }

        private bool ConstructorEndOfData()
        {
            // for the end of data the are 2 possible cases:
            // * value is definite, just compute length by addition
            // * for indefinite: check if current offset points to a 'special' frame

            X690DecodedNode currentConstructor = constructorsStack.Peek();

            //if (currentConstructor.ContentLength)
            {
                bool isFrameAfterConstuctorData =
                    (currentConstructor.ContentLength +
                    currentConstructor.FrameOffset +
                    currentConstructor.Frame.FrameLength) <= bufferFrame.Offset;


                return isFrameAfterConstuctorData ||
                       currentConstructor.ContentLength == 0;
            }
            //else
            //{
            //    CodingFrame frame = bufferFrame.CodingFrame;
            //    if (frame.ContentLength.IsDefinite)
            //    {
            //        // special frame where frame is encoded as 2 zero bytes
            //        // means that frame decoded from 2 zero bytes (end-of-content) have following values 
            //        // also means that *current* frame points to this null-bytes  == end of data for constructor
            //        return frame.Tag.Class == TagClass.Universal &&
            //               frame.Tag.Number == 0 &&
            //               frame.ContentLength.Length == 0;
            //    }

            //    return false;
            //}
        }

        private void AddToCurrentConstrucor(X690DecodedNode decoded)
        {
            if (constructorsStack.Count == 0)
            {
                throw new X690DeserializerException(bufferFrame, "Constructor stack is empty");
            }

            X690DecodedNode currentConstructor = constructorsStack.Peek();

            currentConstructor.AppendConstructorContent(decoded);
        }
    }
}
