namespace Arctium.Standards.ArctiumLibShared
{
    /// <summary>
    /// Indicates that implementing type can be converted into other type.
    /// Can be usefull sometimes (e.g. converting deserialized SA private key to RSA keys of other types)
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public interface IArctiumConvertable<T>
    {
        /// <summary>
        /// Method that convert implementing type into other type 'T'
        /// </summary>
        /// <returns></returns>
        T Convert();
    }
}
