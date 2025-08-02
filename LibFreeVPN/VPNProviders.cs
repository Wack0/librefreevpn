using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace LibFreeVPN
{
    /// <summary>
    /// Provide operations over available VPN providers.
    /// </summary>
    public static class VPNProviders
    {
        private class Enumerable : IEnumerable<IVPNProvider>
        {
            public IEnumerator<IVPNProvider> GetEnumerator()
            {
                return s_VpnProviders.GetEnumerator();
            }

            IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        }
        private readonly static List<IVPNProvider> s_VpnProviders = new List<IVPNProvider>();
        
        static VPNProviders()
        {
            // Get all IVPNProviders by reflection
            var typeInterface = typeof(IVPNProvider);
            foreach (var type in AppDomain.CurrentDomain.GetAssemblies().SelectMany(asm => asm.GetTypes()).Where(type =>
                typeInterface.IsAssignableFrom(type) && type.IsPublic && !type.IsInterface && !type.IsAbstract
            ))
            {
                // Try to create instance (ignore it on failure), and add created object to the list
                try
                {
                    s_VpnProviders.Add((IVPNProvider)Activator.CreateInstance(type));
                }
                catch { }
            }
        }

        /// <summary>
        /// Gets an iterator of providers.
        /// </summary>
        public static IEnumerable<IVPNProvider> Providers => new Enumerable();
    }
}
