using LibFreeVPN.Servers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace LibFreeVPN.Providers
{
    // iOS app. v2ray using "Surge" client. C2 is a github repo.
    // Configs are split by "country" but this seems meaningless, one check of "US" config gave two endpoints, one in .nl and one in .dk
    // Configs are updated multiple times per hour.
    // Each config includes at least one endpoint entunneling through websockets on cloudflare with randomly generated registered domains.
    public sealed class BeautyBird : VPNProviderBase
    {
        private static readonly string s_Name = nameof(BeautyBird);
        public override string Name => s_Name;

        public override string SampleSource => "aHR0cHM6Ly9hcHBzLmFwcGxlLmNvbS91cy9hcHAvdnBuLWZyZWUtdnBuLWZhc3QvaWQ2NTA0NjM1ODcz";

        public override string SampleVersion => "1.1.8";

        public override bool RiskyRequests => false;

        public override bool HasProtocol(ServerProtocol protocol) =>
            protocol == ServerProtocol.V2Ray;

        private static readonly byte[] s_AesKey =
        {
            0x42, 0x34, 0x18, 0x35, 0x29, 0xe5, 0xd9, 0x3e, 0xc1, 0x69, 0x76, 0xa0, 0x40, 0xad, 0x7d, 0xbc,
            0x7c, 0x92, 0x70, 0x8a, 0x0f, 0xf8, 0x5a, 0xb7, 0x0b, 0x83, 0x35, 0xca, 0x7f, 0x4d, 0x37, 0x3d
        };

        private static readonly byte[] s_AesIv =
        {
            0x6a, 0x30, 0x6b, 0x70, 0x7f, 0xa9, 0x22, 0x40, 0x0c, 0x9d, 0x66, 0xa2, 0xbc, 0x6d, 0x12, 0x64
        };

        private static readonly AesManaged s_AesAlgo = new AesManaged()
        {
            Padding = PaddingMode.PKCS7,
            Mode = CipherMode.CBC,
            KeySize = 256,
            BlockSize = 128
        };

        private static readonly string s_RepoName = Encoding.ASCII.GetString(Convert.FromBase64String("R3lyZmFsY29uVlBOL25vZGVz"));

        private static IEnumerable<IVPNServer> ParseJson(JsonElement json)
        {
            var empty = Enumerable.Empty<IVPNServer>();
            return json.EnumerateArray().SelectMany((obj) =>
            {
                if (!obj.TryGetProperty("proxy", out var proxyElem)) return empty;
                var extraRegistry = CreateExtraRegistry(s_Name);
                if (obj.TryGetProperty("name", out var displayNameElem))
                {
                    extraRegistry.Add(ServerRegistryKeys.DisplayName, displayNameElem.GetString());
                }

                return V2RayServerSurge.ParseConfigFull(proxyElem.GetString(), extraRegistry);
            });
        }

        private static async Task<IEnumerable<IVPNServer>> GetServersAsync(string url)
        {
            var httpClient = new HttpClient();
            var cipherText = Convert.FromBase64String(await httpClient.GetStringAsync(url));
            var crypto = s_AesAlgo.CreateDecryptor(s_AesKey, s_AesIv);
            var plainText = Encoding.UTF8.GetString(crypto.TransformFinalBlock(cipherText, 0, cipherText.Length));
            var configJson = JsonDocument.Parse(plainText);
            if (configJson.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
            if (!configJson.RootElement.TryGetProperty("code", out var codeElem)) throw new InvalidDataException();
            if (codeElem.GetInt32() != 0) throw new InvalidDataException();
            if (!configJson.RootElement.TryGetProperty("data", out var dataElem)) throw new InvalidDataException();
            if (dataElem.ValueKind != JsonValueKind.Array) throw new InvalidDataException();
            return ParseJson(dataElem);
        }

        private static async Task<IEnumerable<IVPNServer>> TryGetServersAsync(string url)
        {
            try
            {
                return await GetServersAsync(url);
            } catch
            {
                return Enumerable.Empty<IVPNServer>();
            }
        }

        protected override async Task<IEnumerable<IVPNServer>> GetServersAsyncImpl()
        {
            var httpClient = new HttpClient();
            // Get the list of files in the root of the repository
            HttpResponseMessage listResponse = null;
            using (var listRequest = new HttpRequestMessage(HttpMethod.Get, string.Format("https://github.com/{0}/tree-commit-info/main", s_RepoName)))
            {
                listRequest.Headers.Accept.ParseAdd("application/json");
                listResponse = await httpClient.SendAsync(listRequest);
            }

            var listJsonStr = await listResponse.Content.ReadAsStringAsync();
            var listJson = JsonDocument.Parse(listJsonStr);
            if (listJson.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
            // take the filenames we want, convert them to their URLs
            var configUrls = listJson.RootElement.EnumerateObject()
                .Where((prop) => prop.Name.StartsWith("node") && prop.Name.EndsWith(".txt"))
                .Select((prop) => string.Format("https://raw.githubusercontent.com/{0}/main/{1}", s_RepoName, prop.Name));

            // for each of them, download and parse them all
            var configTasks = configUrls.Select((url) => TryGetServersAsync(url)).ToList();
            // await all the tasks
            await Task.WhenAll(configTasks);

            // and squash them down to one list
            return configTasks.SelectMany((task) => task.Result);
        }
    }
}
