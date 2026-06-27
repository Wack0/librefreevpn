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

// Android app, openvpn. Own-hosted risky C2, split between free and paid configs.
// No trusting client here - can only get paid config with signed ticket from Google Play or Amazon Appstore
namespace LibFreeVPN.Providers
{
    public sealed class Ldcl : VPNProviderBase
    {
        private static readonly string s_BaseUri = Encoding.ASCII.GetString(Convert.FromBase64String("aHR0cHM6Ly9hcGk0LmNhbmR5bGluay5jb20vcHJvZC9hcGkvdjIuMC4wLw=="));
        private static readonly string s_ApiKey = Encoding.ASCII.GetString(Convert.FromBase64String("ckRVWWJXWGFSZDFJY2ZnTUw0V1NQM0l5M2gxdnl2YkIza1BHZVY0UQ=="));
        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5jYW5keWxpbmsub3BlbnZwbg==";

        public override string SampleVersion => "4.2.1";

        public override bool RiskyRequests => true;

        private static readonly string s_RouteCountries = Encoding.ASCII.GetString(Convert.FromBase64String("Y29ubmVjdC9jb3VudHJ5"));
        private static readonly string s_RouteMainConfig = Encoding.ASCII.GetString(Convert.FromBase64String("cmVtb3RlX2NvbmZpZz90eXBlPW1vYmlsZV9jb25maWc="));
        private static readonly string s_RouteCountryConfig = Encoding.ASCII.GetString(Convert.FromBase64String("Y29ubmVjdA=="));

        private static readonly string s_ObtainableCountryElement = Encoding.ASCII.GetString(Convert.FromBase64String("aXNfYXZhaWxhYmxlX2Zvcl9mcmVl"));
        private static readonly string s_MainConfigsElement = Encoding.ASCII.GetString(Convert.FromBase64String("c3RlYWx0aF9tb2RlX2NvbmZpZw=="));

        private static readonly string s_MobileOsElement = Encoding.ASCII.GetString(Convert.FromBase64String("RGV2aWNlT1M="));
        private static readonly string s_RequestType = Encoding.ASCII.GetString(Convert.FromBase64String("Q29ubmVjdA=="));

        public override bool HasProtocol(ServerProtocol protocol)
            => protocol == ServerProtocol.OpenVPN;

        private static string MakeUri(string route)
        {
            var sb = new StringBuilder(s_BaseUri);
            sb.Append(route);
            return sb.ToString();
        }

        private static async Task<string> MakeRequestAsync(string route)
        {
            HttpResponseMessage listResponse = null;
            using (var listRequest = new HttpRequestMessage(HttpMethod.Get, MakeUri(route)))
            {
                listRequest.Headers.Add("x-api-key", s_ApiKey);
                listResponse = await ServerUtilities.HttpClient.SendAsync(listRequest);
            }

            return await listResponse.Content.ReadAsStringAsync();
        }

        private static string MakePostRequestData(string country)
        {
            var attributes = new JsonObject()
            {
                ["Country"] = country,
                [s_MobileOsElement] = "Android"
            };

            var data = new JsonObject()
            {
                ["type"] = s_RequestType,
                ["attributes"] = attributes
            };

            var req = new JsonObject()
            {
                ["data"] = data
            };

            return req.ToJsonString();
        }

        private static async Task<string> MakePostRequestAsync(string route, string country)
        {
            var reqContent = new ByteArrayContent(Encoding.UTF8.GetBytes(MakePostRequestData(country)));
            reqContent.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse("application/json");
            reqContent.Headers.Add("x-api-key", s_ApiKey);
            var response = await ServerUtilities.HttpClient.PostAsync(
                MakeUri(route),
                reqContent
            );
            return await response.Content.ReadAsStringAsync();
        }

        private IEnumerable<IVPNServer> ParseMainConfig(string mainConf)
        {
            try
            {
                var mainConfJson = JsonDocument.Parse(mainConf);
                if (mainConfJson.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
                if (!mainConfJson.RootElement.TryGetProperty("data", out var mainConfData)) throw new InvalidDataException();
                if (mainConfData.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
                if (!mainConfData.TryGetProperty("attributes", out var elemAttributes)) throw new InvalidDataException();
                if (elemAttributes.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
                if (!elemAttributes.TryGetProperty("config", out var elemAttrConfig)) throw new InvalidDataException();
                if (elemAttrConfig.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
                if (!elemAttrConfig.TryGetProperty(s_MainConfigsElement, out var mainConfsObject)) throw new InvalidDataException();
                if (mainConfsObject.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
                if (!mainConfsObject.TryGetProperty("configs", out var serversData)) throw new InvalidDataException();
                if (serversData.ValueKind != JsonValueKind.Array) throw new InvalidDataException();
                return serversData.EnumerateArray().SelectMany((elem) =>
                {
                    try
                    {
                        if (elem.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
                        if (!elem.TryGetPropertyString("FileName", out var confName)) throw new InvalidDataException();
                        if (!elem.TryGetPropertyString("File", out var conf)) throw new InvalidDataException();
                        conf = Encoding.UTF8.GetString(Convert.FromBase64String(conf));
                        var registry = CreateExtraRegistry();
                        registry.Add(ServerRegistryKeys.DisplayName, confName);
                        return OpenVpnServer.ParseConfigFull(conf, registry);
                    } catch { return Enumerable.Empty<IVPNServer>(); }
                }).ToList();
            } catch { return Enumerable.Empty<IVPNServer>(); }
        }

        private async Task<IEnumerable<IVPNServer>> GetAndParseCountryConfigAsync(string country)
        {
            try
            {
                var config = await MakePostRequestAsync(s_RouteCountryConfig, country);
                var mainConfJson = JsonDocument.Parse(config);
                if (mainConfJson.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
                if (!mainConfJson.RootElement.TryGetProperty("data", out var mainConfData)) throw new InvalidDataException();
                if (mainConfData.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
                if (!mainConfData.TryGetProperty("attributes", out var mainConfsObject)) throw new InvalidDataException();
                if (mainConfsObject.ValueKind != JsonValueKind.Object) throw new InvalidDataException();

                if (!mainConfsObject.TryGetPropertyString("FileName", out var confName)) throw new InvalidDataException();
                if (!mainConfsObject.TryGetPropertyString("File", out var conf)) throw new InvalidDataException();
                conf = Encoding.UTF8.GetString(Convert.FromBase64String(conf));
                var registry = CreateExtraRegistry();
                registry.Add(ServerRegistryKeys.DisplayName, confName);
                registry.Add(ServerRegistryKeys.Country, country);
                return OpenVpnServer.ParseConfigFull(conf, registry);
            }
            catch { return Enumerable.Empty<IVPNServer>(); }
        }

        protected override async Task<IEnumerable<IVPNServer>> GetServersAsyncImpl()
        {
            // Get list of countries
            var countries = await MakeRequestAsync(s_RouteCountries);
            var countriesJson = JsonDocument.Parse(countries);
            if (countriesJson.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
            if (!countriesJson.RootElement.TryGetProperty("data", out var countriesData)) throw new InvalidDataException();
            if (countriesData.ValueKind != JsonValueKind.Array) throw new InvalidDataException();
            var countriesList = countriesData.EnumerateArray().SelectMany((elem) =>
            {
                try
                {
                    if (elem.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
                    if (!elem.TryGetProperty("attributes", out var elemAttributes)) throw new InvalidDataException();
                    if (elemAttributes.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
                    if (!elemAttributes.TryGetProperty(s_ObtainableCountryElement, out var isObtainable)) throw new InvalidDataException();
                    if (isObtainable.ValueKind != JsonValueKind.True) throw new InvalidDataException();
                    if (!elemAttributes.TryGetPropertyString("Code", out var country)) throw new InvalidDataException();
                    return country.EnumerableSingle();
                } catch { return Enumerable.Empty<string>(); }
            }).ToList();

            // Get initial set of configs
            var mainConf = await MakeRequestAsync(s_RouteMainConfig);
            var ret = ParseMainConfig(mainConf);

            // Get remaining configs
            var tasks = countriesList.Select((country) => GetAndParseCountryConfigAsync(country)).ToList();
            await Task.WhenAll(tasks);
            return tasks.SelectMany((task) => task.Result).Concat(ret);

        }
    }
}
