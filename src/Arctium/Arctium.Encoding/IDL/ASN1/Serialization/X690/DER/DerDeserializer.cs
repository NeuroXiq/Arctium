using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.Serialization.Exceptions;
using System;
using System.Collections.Generic;

namespace Arctium.Encoding.IDL.ASN1.Serialization.X690.DER
{
    // constructors stack is a recursion but is accomplished by this stack

    public class DerDeserializer
    {
        BufferFrame bufferFrame;
        List<DecodingMetadata> metadata;
        PrimitiveDecoders primitiveDecoders;
        ConstructorDecoders constructorDecoders;
        DerDeserializerConfig config;

        Stack<ConstructorDecoderContext> constructorsStack;

        public DerDeserializer(IConstructorDecoder[] externalConstuctorDecoders = null, IPrimitiveDecoder[] externalPrimitiveDecoders = null)
        {

            primitiveDecoders = new PrimitiveDecoders();
            constructorDecoders = new ConstructorDecoders();
            constructorsStack = new Stack<ConstructorDecoderContext>();

            // assign build-in decoders

            constructorDecoders.AddRange(DerBuildInDecoders.CreateConstructorDecoders());
            primitiveDecoders.AddRange(DerBuildInDecoders.CreatePrimitiveDecoders());

            if (externalConstuctorDecoders != null)
            {
                constructorDecoders.AddRange(externalConstuctorDecoders);
            }
            if (externalPrimitiveDecoders != null)
            {
                primitiveDecoders.AddRange(externalPrimitiveDecoders);
            }

        }

        public DerDeserializationResult Deserialize(byte[] buffer)
        {
            bufferFrame = new BufferFrame(buffer);
            bufferFrame.SeekFromStart(0);
            metadata = new List<DecodingMetadata>();
            ConstructorDecoderContext rootConstructor = new ConstructorDecoderContext();
            rootConstructor.Constructor = new SpecialRootConstructor(buffer.Length);
            rootConstructor.Offset = 0;
            constructorsStack.Push(rootConstructor);

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

                    IPrimitiveDecoder decoder = primitiveDecoders.Get(codingFrame.Tag);
                    long contentLength;
                    long contentOffset = bufferFrame.Offset + bufferFrame.CodingFrame.FrameLength;
                    Asn1TaggedType decoded = decoder.Decode(codingFrame, buffer, contentOffset, out contentLength);

                    AddToCurrentConstrucor(decoded);

                    

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

            DerDeserializationResult result = new DerDeserializationResult();
            result.Metadata = metadata;
            result.RootDecodedValue = ((SpecialRootConstructor)constructorsStack.Pop().Constructor).container;

            return result;
        }

        private int PopCurrentConstructor()
        {
            IConstructorDecoder constructor = constructorsStack.Peek().Constructor;
            var ctor = constructorsStack.Pop();
            constructorsStack.Peek().Constructor.Add(ctor.Constructor.InitializationFrame, ctor.Constructor.GetPopValue());
            if (constructor.InitializationFrame.ContentLength.IsDefinite)
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

            IConstructorDecoder constructor = constructorDecoders.Create(codingFrame.Tag, codingFrame);
            ConstructorDecoderContext constructorDecoderContext = new ConstructorDecoderContext();
            constructorDecoderContext.Constructor = constructor;
            constructorDecoderContext.Offset = bufferFrame.Offset;

            constructorsStack.Push(constructorDecoderContext);
        }

        private bool ConstructorEndOfData()
        {
            // for the end of data the are 2 possible cases:
            // * value is definite, just compute length by addition
            // * for indefinite: check if current offset points to a 'special' frame

            ConstructorDecoderContext constructorContext = constructorsStack.Peek();
            IConstructorDecoder currentConstructor = constructorContext.Constructor;

            if (currentConstructor.InitializationFrame.ContentLength.IsDefinite)
            {
                bool isFrameAfterConstuctorData = 
                    (currentConstructor.InitializationFrame.ContentLength.Length +
                    constructorContext.Offset +
                    currentConstructor.InitializationFrame.FrameLength) <= bufferFrame.Offset;


                return isFrameAfterConstuctorData ||
                       currentConstructor.InitializationFrame.ContentLength.Length == 0;
            }
            else
            {
                CodingFrame frame = bufferFrame.CodingFrame;
                if (frame.ContentLength.IsDefinite)
                {
                    // special frame where frame is decoded from 2 zero bytes
                    // means that frame decoded from 2 zero bytes (end-of-content) have following values 
                    // also means that *current* frame points to this null-bytes  == end of data for constructor
                    return frame.Tag.Class == TagClass.Universal &&
                           frame.Tag.Number == 0 &&
                           frame.ContentLength.Length == 0;
                }

                return false;
            }
        }

        private void AddToCurrentConstrucor(Asn1TaggedType decoded)
        {
            if (constructorsStack.Count == 0)
            {
                throw new X690DeserializerException(bufferFrame, "Constructor stack is empty");
            }

            IConstructorDecoder currentConstructor = constructorsStack.Peek().Constructor;

            if (!currentConstructor.CanPush(bufferFrame.CodingFrame))
            {
                throw new X690DeserializerException(bufferFrame, "Current constructor cannot handle type with this frame in this context");
            }

            currentConstructor.Add(bufferFrame.CodingFrame, decoded);
        }
    }
}
