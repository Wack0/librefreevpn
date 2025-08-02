using System;
using System.Collections.Generic;
using System.Text;

namespace LibFreeVPN
{
    public abstract class VPNServerConfigParserBase<TServer> : IVPNServerConfigParser<TServer>
        where TServer : IVPNServer
    {
        public abstract IEnumerable<(string hostname, string port)> ParseConfig(string config);
        public abstract IEnumerable<(string config, string hostname, string port)> ParseConfigFull(string config);
        public virtual string GetUserVisibleConfig(string config, IReadOnlyDictionary<string, string> registry)
            => config;

        public abstract TServer CreateInstance(string config);
        public abstract TServer CreateInstance(string config, string hostname, string port);
        public abstract TServer CreateInstance(string config, IReadOnlyDictionary<string, string> extraRegistry);
        public abstract TServer CreateInstance(string config, string hostname, string port, IReadOnlyDictionary<string, string> extraRegistry);
        public abstract TServer CreateInstance(string hostname, string port);
        public abstract TServer CreateInstance(string hostname, string port, IReadOnlyDictionary<string, string> extraRegistry);


        public TServer CreateInstance(string config, string hostname, int port) => CreateInstance(config, hostname, port.ToString());

        public TServer CreateInstance(string config, string hostname, int port, IReadOnlyDictionary<string, string> extraRegistry)
            => CreateInstance(config, hostname, port.ToString(), extraRegistry);

        public TServer CreateInstance(string hostname, int port, IReadOnlyDictionary<string, string> extraRegistry)
            => CreateInstance(hostname, port.ToString(), extraRegistry);

        public abstract bool CanCreateInstance(bool withConfig);

        public virtual void AddExtraProperties(IDictionary<string, string> registry, string config) { }
    }
}
