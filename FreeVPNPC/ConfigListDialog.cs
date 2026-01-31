using LibFreeVPN;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace FreeVPNPC
{
    public partial class ConfigListDialog : Form
    {
        private List<IVPNServer> m_Servers;
        private static readonly Dictionary<ServerProtocol, string> s_ProtocolToFilter = new Dictionary<ServerProtocol, string>()
        {
            { ServerProtocol.OpenVPN, "OpenVPN configuration file (*.ovpn)|*.ovpn" },
            { ServerProtocol.WireGuard, "WireGuard configuration file (*.conf)|*.conf" },
            { ServerProtocol.Unknown, "Text file (*.txt)|*.txt" }
        };

        public ConfigListDialog(List<IVPNServer> servers)
        {
            m_Servers = servers;
            InitializeComponent();
        }

        private void ConfigListDialog_Load(object sender, EventArgs e)
        {
            for (int i = 0; i < m_Servers.Count; i++)
            {
                var server = m_Servers[i];
                var sb = new StringBuilder();
                sb.Append('[').Append(server.Protocol).Append("] ");
                if (server.Registry.TryGetValue(ServerRegistryKeys.Country, out var country)) sb.Append('[').Append(country).Append("] ");
                sb.Append(server.Registry[ServerRegistryKeys.ProviderName]).Append('_').Append(server.Registry[ServerRegistryKeys.DisplayName]);
                listBoxServers.Items.Add(sb.ToString());
            }
        }

        private void listBoxServers_SelectedIndexChanged(object sender, EventArgs e)
        {
            textBoxConfig.Text = m_Servers[listBoxServers.SelectedIndex].Config;
        }

        private async void buttonSave_Click(object sender, EventArgs e)
        {
            var server = m_Servers[listBoxServers.SelectedIndex];
            if (!s_ProtocolToFilter.TryGetValue(server.Protocol, out var filter)) filter = s_ProtocolToFilter[ServerProtocol.Unknown];
            var dispNameWithProv = string.Format("{0}_{1}",
                    server.Registry[ServerRegistryKeys.ProviderName],
                    server.Registry[ServerRegistryKeys.DisplayName]);
            var dispName = string.Join("_", dispNameWithProv.Split(Path.GetInvalidFileNameChars())) + ".";
            dispName += filter.Split('.').Last();
            var sfd = new SaveFileDialog()
            {
                Filter = filter,
                RestoreDirectory = true,
                FileName = dispName
            };
            if (sfd.ShowDialog() != DialogResult.OK) return;
            var stream = sfd.OpenFile();
            if (stream == null) return;
            using (var tw = new StreamWriter(stream))
            {
                await tw.WriteAsync(server.Config);
            }
        }
    }
}
