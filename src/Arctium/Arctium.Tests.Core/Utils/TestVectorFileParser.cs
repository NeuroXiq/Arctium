using Arctium.Shared.Helpers.Binary;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Tests.Core.Utils
{
    abstract class PropMap<T>
    {
        public string Name;
        public Type DataType;

        public PropMap(string name, Type dataType)
        {
            Name = name;
            
            DataType = dataType;
        }

        public abstract void SetValue(T instance, string value);
    }

    class PropMapT<T, TProp> : PropMap<T>
    {
        public Action<T, TProp> SetAction;

        public PropMapT(string name, Action<T, TProp> set) : base(name, typeof(TProp))
        {
            SetAction = set;    
        }

        public override void SetValue(T instance, string value)
        {
            TProp v = Parse(value);

            SetAction(instance, v);
        }

        private TProp Parse(string value)
        {
            object p = null;

            if (typeof(TProp) == typeof(byte[]))
            {
                p = BinConverter.FromString(value);
            }
            else if (typeof(TProp) == typeof(int))
            {
                p = int.Parse(value);
            }
            else
            {
                throw new NotSupportedException("not supported parsing " + typeof(TProp).ToString());
            }

            return (TProp)p;
        }
    }

    public class TestVectorFileParser<T>
    {
        List<string> ignoreStartWith = new List<string>();
        List<PropMap<T>> maps = new List<PropMap<T>>();
        string splitLine;
        private string startingPoint;

        public TestVectorFileParser()
        {
            splitLine = "=";
        }

        public List<T> Parse(string fullFileName)
        {
            string[] allLines = File.ReadAllLines(fullFileName);
            var mapped = new List<T>();

            for (int i = 0; i < allLines.Length; i++)
            {
                string line = allLines[i];

                if (ignoreStartWith.Any(s => line.StartsWith(s))) continue;
                if (!line.StartsWith(startingPoint)) continue;

                var instance = Activator.CreateInstance<T>();

                for (int j = 0; j < maps.Count; j++)
                {
                    string[] lineData = allLines[i + j].Split(splitLine);
                    string name = lineData[0].Trim();
                    string data = lineData[1].Trim();


                    ExecuteMap(instance, name, data);
                }

                mapped.Add(instance);

                i += maps.Count - 1;
            }


            return mapped;
        }

        public void StartingPointInFileMapPropertyName(string startingPoint)
        {
            this.startingPoint = startingPoint;
        }

        public void IgnoreStartWith(string startWith)
        {
            ignoreStartWith.Add(startWith);
        }

        public void SplitLine(string s)
        {
            this.splitLine = s;
        }

        public void Map<TDataType>(string name, Action<T, TDataType> action)
        {
            maps.Add(new PropMapT<T, TDataType>(name, action));
        }

        private void ExecuteMap(T instance, string mapName, string mapData)
        {
            var map = maps.Single(m => m.Name == mapName);
            map.SetValue(instance, mapData);
        }
    }
}
