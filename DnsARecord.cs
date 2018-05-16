// -----------------------------------------------------------------------------------------------------------
// <copyright file="DnsARecord.cs" company="">
// Copyright © 2017 Giorgi Chakhidze. All rights reserved.
// </copyright>
// <author>Giorgi Chakhidze</author>
// <email>0xfeeddeadbeef@gmail.com</email>
// <date>Thursday, October 12, 2017 5:27:48 PM</date>
// <summary>Contains the DnsARecord class.</summary>
// -----------------------------------------------------------------------------------------------------------

namespace DnsQuery
{
    using System;
    using System.Net;
    using System.Runtime.InteropServices;

    /// <summary>
    /// Represents a DNS A Record.
    /// </summary>
    public sealed class DnsARecord : DnsRecord
    {
        private UInt32 numericIpAddress;
        private IPAddress ipAddress;

        public DnsARecord()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DnsARecord"/> class.
        /// </summary>
        /// <param name="header">DNS record header.</param>
        /// <param name="dataPointer">Pointer to the data portion of the DNS record.</param>
        internal override void Load(DnsRecordHeader header, IntPtr dataPointer)
        {
            base.Load(header, dataPointer);

            Win32DnsARecord record = Marshal.PtrToStructure<Win32DnsARecord>(dataPointer);
            this.numericIpAddress = record.IpAddress;
            this.ipAddress = new IPAddress((long)record.IpAddress);
        }

        /// <summary>
        /// Gets the matching type of DNS dnsRecord.
        /// </summary>
        /// <value>The type of the dnsRecord.</value>
        internal override DnsRecordType RecordType
        {
            get { return DnsRecordType.A; }
        }

        public uint NumericIPAddress
        {
            get { return this.numericIpAddress; }
        }

        public IPAddress IPAddress
        {
            get { return this.ipAddress; }
        }

        /// <summary>
        /// Win32DnsARecord - native format A record returned by DNS API (DNS_A_DATA).
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct Win32DnsARecord
        {
            /// <summary>Represents the common DNS record header.</summary>
            public DnsRecordHeader Header;

            /// <summary>
            /// IPv4 address of host.
            /// </summary>
            public UInt32 IpAddress;
        }

        public override string ToString() => this.ipAddress.ToString();
    }
}
