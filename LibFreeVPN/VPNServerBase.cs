using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace LibFreeVPN
{
    public abstract class VPNServerBase : IVPNServer
    {
        protected readonly Dictionary<string, string> m_Registry = new Dictionary<string, string>();
        public abstract ServerProtocol Protocol { get; }
        public virtual string Config => string.Empty;
        public IReadOnlyDictionary<string, string> Registry => m_Registry;
        public bool Equals(IVPNServer other)
        {
            if (Protocol != other.Protocol) return false;
            if (Registry.TryGetValue(ServerRegistryKeys.Hostname, out var xHost) && other.Registry.TryGetValue(ServerRegistryKeys.Hostname, out var yHost))
                return xHost == yHost;
            return Config == other.Config;
        }

        public override int GetHashCode()
        {
            var hashProtocol = Protocol.GetHashCode();
            if (!Registry.TryGetValue(ServerRegistryKeys.Hostname, out var strToHash))
                strToHash = Config;
            return hashProtocol ^ strToHash.GetHashCode();
        }

        protected VPNServerBase() { }

        public VPNServerBase(string hostname, string port)
        {
            m_Registry.Add(ServerRegistryKeys.Hostname, hostname);
            m_Registry.Add(ServerRegistryKeys.Port, port);
        }

        public VPNServerBase(string hostname, string port, string username) : this(hostname, port)
        {
            m_Registry.Add(ServerRegistryKeys.Username, username);
        }

        public VPNServerBase(string hostname, string port, string username, string password) : this(hostname, port, username)
        {
            m_Registry.Add(ServerRegistryKeys.Password, password);
        }
    }

    /// <summary>
    /// Base class for VPN servers where configs are parsed.
    /// </summary>
    /// <typeparam name="TSelf">Type of self</typeparam>
    /// <typeparam name="TParser">Config parser</typeparam>
    public abstract class VPNServerBase<TSelf, TParser> : VPNServerBase
        where TSelf : VPNServerBase<TSelf, TParser>
        where TParser : IVPNServerConfigParser<TSelf>, new()
    {
        private static readonly TParser s_Parser = new TParser();

        private readonly string m_Config;

        public override string Config => s_Parser.GetUserVisibleConfig(m_Config, m_Registry);

        public VPNServerBase(string config)
        {
            m_Config = config;
        }

        public VPNServerBase(string config, string hostname, string port) : this(config)
        {
            m_Registry.Add(ServerRegistryKeys.Hostname, hostname);
            m_Registry.Add(ServerRegistryKeys.Port, port);
        }

        public VPNServerBase(string config, IReadOnlyDictionary<string, string> extraRegistry) : this(config)
        {
            foreach (var pair in extraRegistry) m_Registry.Add(pair.Key, pair.Value);
        }

        public VPNServerBase(string config, string hostname, string port, IReadOnlyDictionary<string, string> extraRegistry) : this(config, hostname, port)
        {
            foreach (var pair in extraRegistry) m_Registry.Add(pair.Key, pair.Value);
        }

        public static IEnumerable<TSelf> ParseConfig(string config)
        {
            if (!s_Parser.CanCreateInstance(false)) return Enumerable.Empty<TSelf>();
            var extraRegistry = new Dictionary<string, string>();
            s_Parser.AddExtraProperties(extraRegistry, config);
            return s_Parser.ParseConfig(config).Select((tuple) => s_Parser.CreateInstance(tuple.hostname, tuple.port, extraRegistry));
        }

        public static IEnumerable<TSelf> ParseConfig(string config, Dictionary<string, string> extraRegistry)
        {
            if (!s_Parser.CanCreateInstance(false)) return Enumerable.Empty<TSelf>();
            s_Parser.AddExtraProperties(extraRegistry, config);
            return s_Parser.ParseConfig(config).Select((tuple) => s_Parser.CreateInstance(tuple.hostname, tuple.port, extraRegistry));
        }

        public static IEnumerable<TSelf> ParseConfigFull(string config)
        {
            if (!s_Parser.CanCreateInstance(true)) return Enumerable.Empty<TSelf>();
            var extraRegistry = new Dictionary<string, string>();
            s_Parser.AddExtraProperties(extraRegistry, config);
            return s_Parser.ParseConfigFull(config).Select((tuple) => s_Parser.CreateInstance(tuple.config, tuple.hostname, tuple.port, extraRegistry));
        }

        public static IEnumerable<TSelf> ParseConfigFull(string config, Dictionary<string, string> extraRegistry)
        {
            if (!s_Parser.CanCreateInstance(true)) return Enumerable.Empty<TSelf>();
            s_Parser.AddExtraProperties(extraRegistry, config);
            return s_Parser.ParseConfigFull(config).Select((tuple) => s_Parser.CreateInstance(tuple.config, tuple.hostname, tuple.port, extraRegistry));
        }
    }
}
