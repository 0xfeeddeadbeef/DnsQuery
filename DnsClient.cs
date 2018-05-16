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
    using System.Collections.Generic;
    using System.Net;
    using System.Runtime.InteropServices;

    /// <summary>
    /// DNS Query client.
    /// </summary>
    public static class DnsClient
    {
        /// <summary>Win32 successful operation code.</summary>
        private const int ERROR_SUCCESS = 0;

        /// <summary>
        /// Map type of DnsRecord to DnsRecordType.
        /// </summary>
        private static Lazy<Dictionary<Type, DnsRecordType>> typeToDnsTypeMap =
            new Lazy<Dictionary<Type, DnsRecordType>>(() =>
                // TODO: Dont forget to add new record types here!
                new Dictionary<Type, DnsRecordType>
                {
                    { typeof(DnsARecord), DnsRecordType.A },
                    { typeof(DnsAAAARecord), DnsRecordType.AAAA },
                    { typeof(DnsCnameRecord), DnsRecordType.CNAME },
                    { typeof(DnsPtrRecord), DnsRecordType.PTR },
                    { typeof(DnsSoaRecord), DnsRecordType.SOA },
                    { typeof(DnsSrvRecord), DnsRecordType.SRV },
                    { typeof(DnsTxtRecord), DnsRecordType.TXT },
                }, isThreadSafe: true);

        public static bool IsSupported
        {
            get { return Environment.OSVersion.Platform == PlatformID.Win32NT; }
        }

        // TODO: Implement
        public static IEnumerable<DnsRecord> DnsQuery(DnsRecordType recordType, string domain, IPAddress dnsServerAddress)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Perform DNS Query.
        /// </summary>
        /// <typeparam name="T">DnsRecord type.</typeparam>
        /// <param name="domain">The domain.</param>
        /// <param name="dnsServerAddress">IPAddress of DNS server to use (may be null).</param>
        /// <returns>The DNS record list (never null but may be empty).</returns>
        public static IEnumerable<T> DnsQuery<T>(string domain, IPAddress dnsServerAddress) where T : DnsRecord, new()
        {
            // Each strongly-typed DnsRecord type maps to a DnsRecordType enum.
            DnsRecordType dnsRecordTypeToQuery = typeToDnsTypeMap.Value[typeof(T)];

            // queryResultsPtr will point to unmanaged heap memory if DnsQuery succeeds.
            IntPtr queryResultsPtr = IntPtr.Zero;

            try
            {
                int errorCode = DnsNativeMethods.DnsQuery(
                    domain,
                    dnsServerAddress,
                    dnsRecordTypeToQuery,
                    ref queryResultsPtr);

                if (errorCode == ERROR_SUCCESS)
                {
                    DnsRecordHeader dnsRecordHeader;

                    // Interate through linked list of query result records
                    for (IntPtr recordPtr = queryResultsPtr; !recordPtr.Equals(IntPtr.Zero); recordPtr = dnsRecordHeader.NextRecord)
                    {
                        dnsRecordHeader = Marshal.PtrToStructure<DnsRecordHeader>(recordPtr);

                        T dnsRecord = new T();

                        if (dnsRecordHeader.RecordType == dnsRecord.RecordType)
                        {
                            dnsRecord.Load(dnsRecordHeader, recordPtr);

                            yield return dnsRecord;
                        }
                    }
                }
                else
                {
                    throw new DnsException(errorCode);
                }
            }
            finally
            {
                if (queryResultsPtr != IntPtr.Zero)
                {
                    DnsNativeMethods.FreeDnsQueryResults(queryResultsPtr);
                }
            }
        }
    }
}
