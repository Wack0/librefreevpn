using LibFreeVPN.Servers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace LibFreeVPN.Providers
{
    // Android apps. v2ray(vless) with regular v2ray-client json config. C2 is custom servers, pointed to by a github repo.
    // Some iterations point to dummy configs on github.
    public sealed class Aob : VPNProviderBase
    {
        private static readonly string s_Name = nameof(Aob);
        public override string Name => s_Name;

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5mdG9vbHMuYnJhdmV2cG4=";

        public override string SampleVersion => "13.6";

        public override bool RiskyRequests => true;

        public override bool HasProtocol(ServerProtocol protocol) =>
            protocol == ServerProtocol.V2Ray;

        private static readonly string s_RepoName = Encoding.ASCII.GetString(Convert.FromBase64String("YXBwb25ib2FyZDIwMTkvYXBp"));

        private static readonly string s_DisplayNameKey = Encoding.ASCII.GetString(Convert.FromBase64String("c2VydmVyX2lk"));
        private static readonly string s_CountryKey = Encoding.ASCII.GetString(Convert.FromBase64String("aG9zdG5hbWU="));

        private static readonly string s_FirstToSecondKey = Encoding.ASCII.GetString(Convert.FromBase64String("YmFja2VuZFVybHM="));

        private static IEnumerable<IVPNServer> ParseJson(JsonElement json)
        {
            var empty = Enumerable.Empty<IVPNServer>();
            return json.EnumerateArray().SelectMany((obj) =>
            {
                if (!obj.TryGetProperty("config", out var config)) return empty;

                var extraRegistry = CreateExtraRegistry(s_Name);

                if (obj.TryGetProperty(s_DisplayNameKey, out var displayName))
                {
                    extraRegistry.Add(ServerRegistryKeys.DisplayName, displayName.GetString());
                }

                if (obj.TryGetProperty(s_CountryKey, out var country))
                {
                    extraRegistry.Add(ServerRegistryKeys.Country, country.GetString());
                }

                return V2RayServer.ParseConfigFull(config.ToString(), extraRegistry);
            });
        }

        private static async Task<IEnumerable<IVPNServer>> GetServersAsync(string url)
        {
            var httpClient = ServerUtilities.HttpClient;
            var firstConf = await httpClient.GetStringAsync(url);
            var firstJson = JsonDocument.Parse(firstConf);
            if (firstJson.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
            if (!firstJson.RootElement.TryGetProperty(s_FirstToSecondKey, out var backendElem)) throw new InvalidDataException();
            if (backendElem.ValueKind != JsonValueKind.Array) throw new InvalidDataException();
            string secondConf = null;
            foreach (var valueJson in backendElem.EnumerateArray())
            {
                try
                {
                    var secondUrl = valueJson.GetString();
                    if (secondUrl.StartsWith("https://raw.githubusercontent.com/")) continue;
                    secondConf = await httpClient.GetStringAsync(secondUrl);
                    break;
                } catch { }
            }

            if (string.IsNullOrEmpty(secondConf)) throw new InvalidDataException();

            var secondJson = JsonDocument.Parse(secondConf);

            if (secondJson.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
            if (!secondJson.RootElement.TryGetProperty("servers", out var serversElem)) throw new InvalidDataException();
            if (serversElem.ValueKind != JsonValueKind.Array) throw new InvalidDataException();

            return ParseJson(serversElem);
        }

        private static async Task<IEnumerable<IVPNServer>> TryGetServersAsync(string url)
        {
            try
            {
                return await GetServersAsync(url);
            }
            catch
            {
                return Enumerable.Empty<IVPNServer>();
            }
        }

        protected override async Task<IEnumerable<IVPNServer>> GetServersAsyncImpl()
        {
            var httpClient = ServerUtilities.HttpClient;
            // Get the list of files in the root of the repository
            HttpResponseMessage listResponse = null;
            using (var listRequest = new HttpRequestMessage(HttpMethod.Get, string.Format("https://github.com/{0}/tree-commit-info/master", s_RepoName)))
            {
                listRequest.Headers.Accept.ParseAdd("application/json");
                listResponse = await httpClient.SendAsync(listRequest);
            }

            var listJsonStr = await listResponse.Content.ReadAsStringAsync();
            var listJson = JsonDocument.Parse(listJsonStr);
            if (listJson.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
            // take the filenames we want, convert them to their URLs
            var configUrls = listJson.RootElement.EnumerateObject()
                .Where((prop) => prop.Name.EndsWith(".txt"))
                .Select((prop) => string.Format("https://raw.githubusercontent.com/{0}/master/{1}", s_RepoName, prop.Name));

            // for each of them, download and parse them all
            var configTasks = configUrls.Select((url) => TryGetServersAsync(url)).ToList();
            // await all the tasks
            await Task.WhenAll(configTasks);

            // and squash them down to one list
            return configTasks.SelectMany((task) => task.Result).Distinct();
        }
    }
}
