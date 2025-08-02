using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace LibFreeVPN
{
    public abstract class VPNServerConfigParserFullBase<TServer> : VPNServerConfigParserBase<TServer>
        where TServer : IVPNServer
    {
        public sealed override IEnumerable<(string hostname, string port)> ParseConfig(string config)
        {
            return ParseConfigFull(config).Select((tuple) => (tuple.hostname, tuple.port));
        }
    }
}
