using LibFreeVPN.Servers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace LibFreeVPN.Providers.Vlist
{
    // Android apps. Base64 encoded list of v2ray urls.
    public abstract class VlistBase : VPNProviderBase
    {
        protected abstract string RequestUri { get; }

        public override bool RiskyRequests => false;

        public override bool HasProtocol(ServerProtocol protocol)
        {
            return protocol == ServerProtocol.V2Ray;
        }

        protected override async Task<IEnumerable<IVPNServer>> GetServersAsyncImpl()
        {
            var httpClient = ServerUtilities.HttpClient;
            // Get the single config file used here.
            var config = await httpClient.GetStringAsync(RequestUri);
            config = Encoding.UTF8.GetString(Convert.FromBase64String(config));

            // And try to parse it
            return config.Split('\n')
                .Where((line) => !string.IsNullOrEmpty(line))
                .SelectMany((line) => V2RayServer.ParseConfigFull(line, CreateExtraRegistry()))
                .Where((server) => server.Registry[ServerRegistryKeys.Hostname] != "0.0.0.0")
                .Distinct()
                .ToList();
        }
    }

    public sealed class VlistBla : VlistBase
    {
        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5ibGFibGFfc29mdHdhcmUudnBu";

        public override string SampleVersion => "1.1.5";

        protected override string RequestUri => Encoding.ASCII.GetString(Convert.FromBase64String("aHR0cHM6Ly9kcml2ZS5nb29nbGUuY29tL3VjP2lkPTFoLUI3bF9YcHAzdVozSlJYNDBienFNSmVCUkpSc2FxTCZleHBvcnQ9ZG93bmxvYWQ="));
    }
}
