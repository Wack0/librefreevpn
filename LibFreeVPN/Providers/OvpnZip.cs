using LibFreeVPN.Servers;
using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using ICSharpCode.SharpZipLib.Zip;

// Android apps. OpenVPN, with several layers of memecrypto (AES + zip password (any crypto variant) + AES)
namespace LibFreeVPN.Providers.OvpnZip
{
    public abstract class OvpnZipBase : VPNProviderBase
    {
        public override bool RiskyRequests => true;

        protected abstract string RequestUri { get; }

        protected abstract byte[] MainKey { get; }
        protected abstract byte[] MainIv { get; }
        protected abstract byte[] ZipKey { get; }
        protected abstract byte[] ZipIv { get; }


        public override bool HasProtocol(ServerProtocol protocol)
            => protocol == ServerProtocol.OpenVPN;

        private static byte[] AesDecrypt(byte[] cipherTextBytes, byte[] key, byte[] iv)
        {
            using (var aes = new AesManaged())
            {
                aes.BlockSize = 128;
                aes.KeySize = 128;
                aes.Padding = PaddingMode.PKCS7;
                using (var dec = aes.CreateDecryptor(key, iv))
                {
                    return dec.TransformFinalBlock(cipherTextBytes, 0, cipherTextBytes.Length);
                }
            }
        }

        private byte[] DecryptZip(byte[] bytes) => AesDecrypt(bytes, ZipKey, ZipIv);
        private string DecryptConf(byte[] bytes) => Encoding.UTF8.GetString(AesDecrypt(bytes, MainKey, MainIv));
        private string DecryptElem(string str) => Encoding.UTF8.GetString(AesDecrypt(Convert.FromBase64String(str), MainKey, MainIv));

        private static readonly byte[] s_PostData =
            Convert.FromBase64String("TWVzc2FnZUZpbGVNeT1NZXNzYWdlRmlsZU15JlBhc3NGaWxlPVBhc3NGaWxlJkZpbGVzPUZpbGVzJlZlcnNpb25GaWxlPVZlcnNpb25GaWxlJk1lc3NhZ2VGaWxlVGg9TWVzc2FnZUZpbGVUaCZNZXNzYWdlRmlsZUVuPU1lc3NhZ2VGaWxlRW4m");

        private static readonly string s_PasswordElement = Encoding.ASCII.GetString(Convert.FromBase64String("UGFzc0ZpbGU="));
        private static readonly string s_ConfsElement = Encoding.ASCII.GetString(Convert.FromBase64String("RmlsZXM="));

        private async Task<IEnumerable<IVPNServer>> GetServersAsync(string url, string password)
        {
            // download and decrypt the zip
            var httpClient = ServerUtilities.HttpClient;
            var zipBytes = DecryptZip(await httpClient.GetByteArrayAsync(url));

            var list = new List<KeyValuePair<string, string>>();

            // extract and decrypt each config from the zip
            using (var zipMs = new MemoryStream(zipBytes))
            using (var zip = new ZipFile(zipMs))
            {
                zip.Password = password;

                foreach (var entry in zip.OfType<ZipEntry>().Where((entry) => !entry.IsDirectory))
                {
                    try
                    {
                        var bytes = new byte[(int)entry.Size];
                        using (var stream = zip.GetInputStream(entry))
                        {
                            await stream.ReadAsync(bytes, 0, bytes.Length);
                        }
                        var conf = DecryptConf(bytes);
                        list.Add(new KeyValuePair<string, string>(entry.Name, conf));
                    }
                    catch { }
                }
            }

            // parse each config
            return list.SelectMany((kv) =>
            {
                var conf = kv.Value;
                var registry = CreateExtraRegistry();
                registry.Add(ServerRegistryKeys.DisplayName, Path.GetFileName(kv.Key));
                // Remove some part of the config that vanilla OpenVPN doesn't like.
                var offStart = conf.IndexOf("<slow>");
                var offEnd = conf.IndexOf("</slow>");
                if (offStart != -1 && offEnd != -1)
                {
                    offEnd += "</slow>".Length;
                    conf = conf.Substring(0, offStart) + conf.Substring(offEnd);
                }
                return OpenVpnServer.ParseConfigFull(conf, registry);
            });
        }

        private async Task<IEnumerable<IVPNServer>> TryGetServersAsync(string url, string password)
        {
            try
            {
                return await GetServersAsync(url, password);
            }
            catch
            {
                return Enumerable.Empty<IVPNServer>();
            }
        }

        protected override async Task<IEnumerable<IVPNServer>> GetServersAsyncImpl()
        {
            var httpClient = ServerUtilities.HttpClient;
            var reqContent = new ByteArrayContent(s_PostData);
            reqContent.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse("application/x-www-form-urlencoded");
            var post = await httpClient.PostAsync(
                RequestUri,
                reqContent
            );

            var content = await post.Content.ReadAsStringAsync();
            var json = JsonDocument.Parse(content);
            if (json.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException();

            // get the zip password
            if (!json.RootElement.TryGetPropertyString(s_PasswordElement, out var password)) throw new InvalidDataException();
            password = DecryptElem(password);

            // get the files object as string
            if (!json.RootElement.TryGetPropertyString(s_ConfsElement, out var confsStr)) throw new InvalidDataException();
            var confsJson = JsonDocument.Parse(confsStr.Replace("\n", ""));
            if (confsJson.RootElement.ValueKind != JsonValueKind.Array) throw new InvalidDataException();
            // get the URLs
            var configUrls = confsJson.RootElement.EnumerateArray().SelectMany((elem) =>
            {
                if (elem.ValueKind != JsonValueKind.Object) return Enumerable.Empty<string>();
                if (!elem.TryGetPropertyString("url", out var url)) return Enumerable.Empty<string>();
                return DecryptElem(url).EnumerableSingle();
            });


            // for each of them, download and parse them all
            var configTasks = configUrls.Select((url) => TryGetServersAsync(url, password)).ToList();
            // await all the tasks
            await Task.WhenAll(configTasks);

            // and squash them down to one list
            return configTasks.SelectMany((task) => task.Result).Distinct();
        }
    }

    public sealed class OvpnZipPdv : OvpnZipBase
    {
        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPXBsYWR1ay5wbGFkdWsuYXBwdnBu";

        public override string SampleVersion => "28";

        protected override string RequestUri =>
            Encoding.ASCII.GetString(Convert.FromBase64String("aHR0cDovL3dpbjk5LnNtdGhhaTRnLndpbi9wbGFkdWtfd3MvZmlsZS8="));

        protected override byte[] MainKey => Convert.FromBase64String("UGxhZHVrVlBOX0tleTAyNA==");

        protected override byte[] MainIv => Convert.FromBase64String("UGxhZHVrVlBOX1ZlYzAyNA==");

        protected override byte[] ZipKey => Convert.FromBase64String("UGxhZHVrWmlwS2V5MjAyNA==");

        protected override byte[] ZipIv => Convert.FromBase64String("UGxhZHVrWmlwVmVjMjAyNA==");
    }
}
