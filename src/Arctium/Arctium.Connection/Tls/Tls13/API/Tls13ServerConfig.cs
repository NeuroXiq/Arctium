namespace Arctium.Connection.Tls.Tls13.API
{
    public class Tls13ServerConfig
    {
        public static Tls13ServerConfig Default { get { return BuildDefault(); } }

        static Tls13ServerConfig BuildDefault()
        {
            return new Tls13ServerConfig();
        }
    }
}
