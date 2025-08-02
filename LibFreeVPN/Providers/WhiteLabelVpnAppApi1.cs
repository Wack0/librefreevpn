using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Linq;
using System.IO;
using LibFreeVPN.Servers;

namespace LibFreeVPN.Providers
{
    public class WhiteLabelVpnAppApi1 : VPNProviderBase
    {
        // example of sample that uses "b25lY29ubmVjdA==" API to provide openvpn configs.
        // POST data, URL, and JSON object keys lightly obfuscated given the nature of the white-labeled API used here.
        // sample may be changed in future if one is found with a higher-plan API key :)
        public override string Name => s_Name;
        private static readonly string s_Name = nameof(WhiteLabelVpnAppApi1);

        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS54bngudnBuYmx1ZXByb3h5";

        public override string SampleVersion => "1.61";

        public override bool RiskyRequests => true;

        public override bool HasProtocol(ServerProtocol protocol)
        {
            return protocol == ServerProtocol.OpenVPN;
        }


        private static readonly string s_ConfigKey = Encoding.ASCII.GetString(Convert.FromBase64String("b3ZwbkNvbmZpZ3VyYXRpb24="));
        private static readonly string s_UsernameKey = Encoding.ASCII.GetString(Convert.FromBase64String("dnBuVXNlck5hbWU="));
        private static readonly string s_PasswordKey = Encoding.ASCII.GetString(Convert.FromBase64String("dnBuUGFzc3dvcmQ="));
        private static readonly string s_DisplayNameKey = Encoding.ASCII.GetString(Convert.FromBase64String("c2VydmVyTmFtZQ=="));
        private static readonly string s_CountryKey = Encoding.ASCII.GetString(Convert.FromBase64String("Y291bnRyeQ=="));
        private static IEnumerable<IVPNServer> ParseJson(JsonDocument json)
        {
            var empty = Enumerable.Empty<IVPNServer>();
            return json.RootElement.EnumerateArray().SelectMany((obj) =>
            {
                if (!obj.TryGetProperty(s_ConfigKey, out var config)) return empty;
                if (!obj.TryGetProperty(s_UsernameKey, out var username)) return empty;
                if (!obj.TryGetProperty(s_PasswordKey, out var password)) return empty;

                var extraRegistry = CreateExtraRegistry(s_Name);
                extraRegistry.Add(ServerRegistryKeys.Username, username.GetString());
                extraRegistry.Add(ServerRegistryKeys.Password, password.GetString());

                if (obj.TryGetProperty(s_DisplayNameKey, out var displayName))
                {
                    extraRegistry.Add(ServerRegistryKeys.DisplayName, displayName.GetString());
                }

                if (obj.TryGetProperty(s_CountryKey, out var country))
                {
                    extraRegistry.Add(ServerRegistryKeys.Country, country.GetString());
                }

                return OpenVpnServer.ParseConfigFull(config.GetString(), extraRegistry);
            });
        }

        private static readonly string s_RequestUri = Encoding.ASCII.GetString(Convert.FromBase64String("aHR0cHM6Ly9kZXZlbG9wZXIub25lY29ubmVjdC50b3Avdmlldy9mcm9udC9jb250cm9sbGVyLnBocA=="));
        private static readonly byte[] s_PostData = Convert.FromBase64String("YWN0aW9uPWZldGNoVXNlclNlcnZlcnMmcGFja2FnZV9uYW1lPWNvbS54bngudnBuYmx1ZXByb3h5JmFwaV9rZXk9QUVJRU1tLlVqSWRQLld0Sy5RdUtjYThZWlFxaVd2blVUR0FRZ2tZcndURXBWYUZpaU4mdHlwZT1wcm8=");
        protected override async Task<IEnumerable<IVPNServer>> GetServersAsyncImpl()
        {
            // single POST request gives out some JSON.
            var httpClient = new HttpClient();
            var reqContent = new ByteArrayContent(s_PostData);
            reqContent.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse("application/x-www-form-urlencoded");
            var post = await httpClient.PostAsync(
                s_RequestUri,
                reqContent
            );

            var content = await post.Content.ReadAsStringAsync();
            var json = JsonDocument.Parse(content);
            // On failure, an object is returned.
            // On success, an array of objects is returned.
            // So if we didn't get an array, throw exception.
            if (json.RootElement.ValueKind != JsonValueKind.Array)
            {
                throw new InvalidDataException();
            }

            return ParseJson(json);
        }
    }
}
