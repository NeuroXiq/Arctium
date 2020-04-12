using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Shared.Helpers.DataStructures
{
    /// <summary>
    /// Dynamic array (Vector)
    /// </summary>
    public class DArray<T> : IEnumerable<T>
    {
        struct DArrayEnumerator : IEnumerator<T>
        {
            int index;

            DArray<T> darray;

            public DArrayEnumerator(DArray<T> darray)
            {
                index = -1;
                this.darray = darray;
            }

            T IEnumerator<T>.Current => darray[index];

            object IEnumerator.Current => ((IEnumerator<T>)this).Current;

            public void Dispose()
            {
            }

            public bool MoveNext()
            {
                if (darray.elementsCount > (index + 1))
                {
                    index++;
                    return true;
                }
                return false;
            }

            public void Reset()
            {
                index = -1;
            }
        }

        const double GrowFactor = 1.4;

        long currentCapacity;
        long elementsCount;
        T[] elements;

        public long Count
        {
            get
            {
                return elementsCount;
            }
        }

        public T this[long index]
        {
            get
            {
                if (index >= elementsCount) throw new IndexOutOfRangeException("Index is outside of bound of the DArray");
                return elements[index];
            }
            set
            {
                elements[index] = value;
            }
        }

        public DArray(long initialCapacity = 16)
        {
            if (initialCapacity < 1) throw new ArgumentException("initialCapacity must be greater than zero");
            this.currentCapacity = initialCapacity;
            elements = new T[initialCapacity];
        }

        /// <summary>
        /// Adds new element to the array as a 
        /// last value in the sequence
        /// </summary>
        /// <param name="value"></param>
        public void Append(T value)
        {
            ExtendIfNeeded(1);
            elements[elementsCount] = value;
            elementsCount++;
        }

        private void ExtendIfNeeded(long appendSize)
        {
            long minCapacity = elementsCount + appendSize;
            if (minCapacity > currentCapacity)
            {
                double newCapacity = currentCapacity * GrowFactor;
                while (newCapacity < minCapacity) newCapacity *= GrowFactor;

                T[] newArray = new T[(long)newCapacity];
                Array.Copy(elements, 0, newArray, 0, elementsCount);
                elements = newArray;
            }
        }


        #region IEnumerable implementation
     
        IEnumerator IEnumerable.GetEnumerator()
        {
            return new DArrayEnumerator(this);
        }

        public IEnumerator<T> GetEnumerator()
        {
            return new DArrayEnumerator(this);
        }

        #endregion
    }
}
