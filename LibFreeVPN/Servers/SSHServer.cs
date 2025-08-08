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

        private static readonly string s_InvalidChars = "'`\";&<>|(){}";

        private static bool ValidUsername(string username)
        {
            // disallow '-' at start
            if (username[0] == '-') return false;
            // disallow '\\' at end
            if (username[username.Length - 1] == '\\') return false;
            for (int i = 0; i < username.Length; i++)
            {
                var chr = new string(username[i], 1);
                if (s_InvalidChars.Contains(chr)) return false;
                // Disallow '-' after whitespace
                if (string.IsNullOrWhiteSpace(chr))
                {
                    if (i < (username.Length - 1) && username[i + 1] == '-') return false;
                }
            }
            return true;
        }

        public SSHServer(string hostname, string port, string username, string password) : base(hostname, port, username, password)
        {
            var sb = new StringBuilder();
            sb.AppendFormat("# Password: {0}", Registry[ServerRegistryKeys.Password]);
            sb.AppendLine();
            // Some providers use shell metacharacters in usernames.
            // OpenSSH 9.6 (specifically, since this commit: https://github.com/openbsd/src/commit/ba05a7aae989020b8d05cc93cc6200109bba5a7b) disallows providing them, as part of a defense in depth approach.
            // The official workaround here is to use an SSH config file.
            // Reimplement the username checks done by OpenSSH and provide a note here.
            if (!ValidUsername(Registry[ServerRegistryKeys.Username]))
            {
                sb.AppendLine("# Username is considered invalid by OpenSSH 9.6 and later when passed on the command line.");
            }
            sb.AppendFormat("ssh -p {2} -D 1080 -q -N -f \"{0}@{1}\"",
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
