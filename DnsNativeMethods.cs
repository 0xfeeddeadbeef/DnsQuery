/*
 * Exchange Web Services Managed API
 *
 * Copyright (c) Microsoft Corporation
 * All rights reserved.
 *
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
 * to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
 * FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

namespace DnsQuery
{
    using System;
    using System.Diagnostics;
    using System.Diagnostics.CodeAnalysis;
    using System.Net;
    using System.Net.Sockets;
    using System.Runtime.InteropServices;
    using System.Security;

    /// <summary>
    /// Class that defined native Win32 DNS API methods
    /// </summary>
    [ComVisible(false)]
    [SuppressUnmanagedCodeSecurity]
    internal static class DnsNativeMethods
    {
        /// <summary>
        /// The Win32 dll from which to load DNS APIs.
        /// </summary>
        /// <remarks>
        /// DNSAPI.DLL has been part of the Win32 API since Win2K. No need to verify that the DLL exists.
        /// </remarks>
        private const string DNSAPI = "dnsapi.dll";

        /// <summary>
        /// Win32 memory free type enumeration.
        /// </summary>
        /// <remarks>Win32 defines other values for this enum but we don't uses them.</remarks>
        private enum FreeType
        {
            /// <summary>
            /// The data freed is a flat structure.
            /// </summary>
            DnsFreeFlat = 0,

            /// <summary>
            /// The data freed is a Resource Record list, and includes subfields of the DNS_RECORD
            /// structure. Resources freed include structures returned by the DnsQuery and DnsRecordSetCopyEx functions.
            /// </summary>
            DnsFreeRecordList = 1,

            /// <summary>
            /// The data freed is a parsed message field.
            /// </summary>
            DnsFreeParsedMessageFields = 2
        }

        /// <summary>
        /// DNS Query options. Options can be combined and all options override DNS_QUERY_STANDARD.
        /// </summary>
        private enum DnsQueryOptions : uint
        {
            /// <summary>
            /// Standard query. MSDN does not explain in detail what &quot;standard&quot; means.
            /// </summary>
            DNS_QUERY_STANDARD = 0x00000000,

            /// <summary>
            /// Returns truncated results. Does not retry under TCP.
            /// </summary>
            DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE = 0x00000001,

            /// <summary>
            /// Uses only TCP for the query.
            /// </summary>
            DNS_QUERY_USE_TCP_ONLY = 0x00000002,

            /// <summary>
            /// Directs the DNS server to perform an iterative query (Specifically directs
            /// the DNS server not to perform recursive resolution to resolve the query).
            /// </summary>
            DNS_QUERY_NO_RECURSION = 0x00000004,

            /// <summary>
            /// Bypasses the resolver cache on the lookup.
            /// </summary>
            DNS_QUERY_BYPASS_CACHE = 0x00000008,

            /// <summary>
            /// Directs DNS to perform a query on the local cache only.
            /// </summary>
            DNS_QUERY_NO_WIRE_QUERY = 0x00000010,

            /// <summary>
            /// Directs DNS to ignore the local name.
            /// </summary>
            DNS_QUERY_NO_LOCAL_NAME = 0x00000020,

            /// <summary>
            /// Prevents the DNS query from consulting the HOSTS file.
            /// </summary>
            DNS_QUERY_NO_HOSTS_FILE = 0x00000040,

            /// <summary>
            /// Prevents the DNS query from using NetBT for resolution.
            /// </summary>
            DNS_QUERY_NO_NETBT = 0x00000080,

            /// <summary>
            /// Directs DNS to perform a query using the network only, bypassing local information.
            /// </summary>
            DNS_QUERY_WIRE_ONLY = 0x00000100,

            /// <summary>
            /// Directs DNS to return the entire DNS response message.
            /// </summary>
            DNS_QUERY_RETURN_MESSAGE = 0x00000200,

            /// <summary>
            /// Prevents the query from using DNS and uses only Local Link Multicast Name Resolution (LLMNR).
            /// </summary>
            DNS_QUERY_MULTICAST_ONLY = 0x00000400,

            /// <summary>
            /// Prevents the query from using Local Link Multicast Name Resolution (LLMNR) and uses only DNS.
            /// </summary>
            DNS_QUERY_NO_MULTICAST = 0x00000800,

            /// <summary>
            /// Prevents the DNS from attaching suffixes to the submitted name in a name resolution process.
            /// </summary>
            DNS_QUERY_TREAT_AS_FQDN = 0x00001000,

            /// <summary>
            /// Starting from Windows 7: Do not send A type queries if IPv4 addresses are not available on
            /// an interface and do not send AAAA type queries if IPv6 addresses are not available.
            /// </summary>
            DNS_QUERY_ADDRCONFIG = 0x00002000,

            /// <summary>
            /// Starting from Windows 7: Query both AAAA and A type records and return results for each.
            /// Results for A type records are mapped into AAAA type.
            /// </summary>
            DNS_QUERY_DUAL_ADDR = 0x00004000,

            /// <summary>
            /// Waits for a full timeout to collect all the responses from the Local Link.
            /// If not set, the default behavior is to return with the first response.
            /// </summary>
            DNS_QUERY_MULTICAST_WAIT = 0x00020000,

            /// <summary>
            /// Directs a test using the local machine hostname to verify name uniqueness on the same Local
            /// Link. Collects all responses even if normal LLMNR Sender behavior is not enabled.
            /// </summary>
            DNS_QUERY_MULTICAST_VERIFY = 0x00040000,

            /// <summary>
            /// If set, and if the response contains multiple records, records are stored with the TTL
            /// corresponding to the minimum value TTL from among all records. When this option is set,
            /// &quot;Do not change the TTL of individual records&quot; in the returned record set is not modified.
            /// </summary>
            DNS_QUERY_DONT_RESET_TTL_VALUES = 0x00100000,

            /// <summary>
            /// Disables International Domain Name (IDN) encoding support in the DnsQuery, DnsQueryEx,
            /// DnsModifyRecordsInSet, and DnsReplaceRecordSet APIs. All punycode names are treated as ASCII
            /// and will be ASCII encoded on the wire. All non-ASCII names are encoded in UTF8 on the wire.
            /// </summary>
            DNS_QUERY_DISABLE_IDN_ENCODING = 0x00200000,

            /// <summary>
            /// Undocumented.
            /// </summary>
            DNS_QUERY_APPEND_MULTILABEL = 0x00800000,

            /// <summary>
            /// Undocumented.
            /// </summary>
            DNS_QUERY_DNSSEC_OK = 0x01000000,

            /// <summary>
            /// Undocumented.
            /// </summary>
            DNS_QUERY_DNSSEC_CHECKING_DISABLED = 0x02000000,

            /// <summary>
            /// Reserved.
            /// </summary>
            DNS_QUERY_RESERVED = 0xF0000000,
        }

        /// <summary>
        /// Represents the native format of a DNS record returned by the Win32 DNS API
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DnsServerList
        {
            public int AddressCount;
            public int ServerAddress;
        }

        /// <summary>
        /// Call Win32 DNS API DnsQuery.
        /// </summary>
        /// <param name="pszName">Host name.</param>
        /// <param name="wType">DNS Record type.</param>
        /// <param name="options">DNS Query options.</param>
        /// <param name="aipServers">Array of DNS server IP addresses.</param>
        /// <param name="ppQueryResults">Query results.</param>
        /// <param name="pReserved">Reserved argument.</param>
        /// <returns>WIN32 status code</returns>
        /// <remarks>For aipServers, DnsQuery expects either null or an array of one IPv4 address.</remarks>
        [SuppressMessage("Microsoft.Security", "CA2118:ReviewSuppressUnmanagedCodeSecurityUsage", Justification = "Managed API")]
        [DllImport(DNSAPI, EntryPoint = "DnsQuery_W", CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern int DnsQuery(
            [In] string pszName,
            DnsRecordType wType,
            DnsQueryOptions options,
            IntPtr aipServers,  // Uncodumented on MSDN!
            ref IntPtr ppQueryResults,
            int pReserved);

        /// <summary>
        /// Call Win32 DNS API DnsRecordListFree.
        /// </summary>
        /// <param name="ptrRecords">DNS records pointer</param>
        /// <param name="freeType">Record List Free type</param>
        [SuppressMessage("Microsoft.Security", "CA2118:ReviewSuppressUnmanagedCodeSecurityUsage", Justification = "Managed API")]
        [DllImport(DNSAPI, EntryPoint = "DnsRecordListFree", CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern void DnsRecordListFree([In] IntPtr ptrRecords, [In] FreeType freeType);

        /// <summary>
        /// Allocate the DNS server list.
        /// </summary>
        /// <param name="dnsServerAddress">The DNS server address (may be null).</param>
        /// <returns>Pointer to DNS server list (may be IntPtr.Zero).</returns>
        private static IntPtr AllocDnsServerList(IPAddress dnsServerAddress)
        {
            IntPtr pServerList = IntPtr.Zero;

            // Build DNS server list arg if DNS server address was passed in.
            // Note: DnsQuery only supports a single IP address and it has to
            // be an IPv4 address.
            if (dnsServerAddress != null)
            {
                Debug.Assert(
                    dnsServerAddress.AddressFamily == AddressFamily.InterNetwork,
                    "DnsNativeMethods",
                    "Only IPv4 DNS server addresses are supported by DnsQuery");

                int serverAddress = BitConverter.ToInt32(dnsServerAddress.GetAddressBytes(), 0);
                DnsServerList serverList;
                serverList.AddressCount = 1;
                serverList.ServerAddress = serverAddress;

                pServerList = Marshal.AllocHGlobal(Marshal.SizeOf(serverList));
                Marshal.StructureToPtr(serverList, pServerList, false);
            }

            return pServerList;
        }

        /// <summary>
        /// Wrapper method to perform DNS Query.
        /// </summary>
        /// <remarks>Makes DnsQuery a little more palatable.</remarks>
        /// <param name="domain">The domain.</param>
        /// <param name="dnsServerAddress">IPAddress of DNS server (may be null) </param>
        /// <param name="recordType">Type of DNS dnsRecord.</param>
        /// <param name="ppQueryResults">Pointer to pointer to query results.</param>
        /// <returns>Win32 status code.</returns>
        internal static int DnsQuery(
            string domain,
            IPAddress dnsServerAddress,
            DnsRecordType recordType,
            ref IntPtr ppQueryResults)
        {
            Debug.Assert(!string.IsNullOrEmpty(domain), "domain cannot be null.");

            IntPtr pServerList = IntPtr.Zero;

            try
            {
                pServerList = AllocDnsServerList(dnsServerAddress);

                return DnsQuery(
                    domain,
                    recordType,
                    DnsQueryOptions.DNS_QUERY_STANDARD,
                    /*  TODO: Experiment with these:
                        DnsQueryOptions.DNS_QUERY_WIRE_ONLY |
                        DnsQueryOptions.DNS_QUERY_NO_HOSTS_FILE |
                        DnsQueryOptions.DNS_QUERY_NO_NETBT |
                        DnsQueryOptions.DNS_QUERY_NO_MULTICAST |
                        DnsQueryOptions.DNS_QUERY_TREAT_AS_FQDN,*/
                    pServerList,
                    ref ppQueryResults,
                    0);
            }
            finally
            {
                // Note: if pServerList is IntPtr.Zero, FreeHGlobal does nothing.
                Marshal.FreeHGlobal(pServerList);
            }
        }

        /// <summary>
        /// Frees memory allocated for DNS records obtained using the DnsQuery function.
        /// </summary>
        /// <param name="ptrRecords">
        /// A pointer to a DNS_RECORD structure that contains the list of DNS records to be freed.
        /// </param>
        /// <remarks>Makes DnsRecordListFree a little more palatable.</remarks>
        internal static void FreeDnsQueryResults(IntPtr ptrRecords)
        {
            Debug.Assert(!ptrRecords.Equals(IntPtr.Zero), "ptrRecords cannot be null.");

            DnsRecordListFree(ptrRecords, FreeType.DnsFreeRecordList);
        }
    }
}
