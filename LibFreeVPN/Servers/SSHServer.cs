using System;
using System.Collections.Generic;
using System.Text;

namespace LibFreeVPN.Servers
{
    public class SSHServer : VPNServerBase
    {
        public override ServerProtocol Protocol => ServerProtocol.SSH;

        private readonly string m_Config;

        public override string Config => m_Config;

        public SSHServer(string hostname, string port, string username, string password) : base(hostname, port, username, password)
        {
            var sb = new StringBuilder();
            sb.AppendFormat("# Password: {0}", Registry[ServerRegistryKeys.Password]);
            sb.AppendLine();
            sb.AppendFormat("ssh -p {2} -D 1080 -q -N -f {0}@{1}",
                Registry[ServerRegistryKeys.Username],
                Registry[ServerRegistryKeys.Hostname],
                Registry[ServerRegistryKeys.Port]);
            sb.AppendLine();
            m_Config = sb.ToString();
        }

        public SSHServer(string hostname, string port, string username, string password, IReadOnlyDictionary<string, string> extraRegistry) : this(hostname, port, username, password)
        {
            foreach (var pair in extraRegistry) m_Registry.Add(pair.Key, pair.Value);
        }
    }
}
