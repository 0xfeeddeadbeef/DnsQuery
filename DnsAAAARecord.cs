// -----------------------------------------------------------------------------------------------------------
// <copyright file="DnsAAAARecord.cs" company="">
// Copyright © 2018 Giorgi Chakhidze. All rights reserved.
// </copyright>
// <author>Giorgi Chakhidze</author>
// <email>0xfeeddeadbeef@gmail.com</email>
// <date>Monday, April 30, 2018 3:08:08 PM</date>
// <summary>Contains the DnsAAAARecord class.</summary>
// -----------------------------------------------------------------------------------------------------------

namespace DnsQuery
{
    using System;
    using System.Net;
    using System.Numerics;
    using System.Runtime.InteropServices;

    /// <summary>
    /// Represents a DNS AAAA Record.
    /// </summary>
    public sealed class DnsAAAARecord : DnsRecord
    {
        private BigInteger numericIp6Address;
        private IPAddress ipAddress;

        private DnsAAAARecord()
        {
        }

        private sealed class SafeDnsAAAABuffer : SafeBuffer
        {
            public SafeDnsAAAABuffer(IntPtr address)
                : base(ownsHandle: false)
            {
                this.SetHandle(address);
            }

            protected override bool ReleaseHandle()
            {
                // We dont have to do anything, because:
                //  - This object does not own the buffer
                //  - FreeDnsQueryResults will release memory eventually
                return true;
            }

            public override bool IsInvalid
            {
                get { return this.handle == IntPtr.Zero; }
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DnsAAAARecord"/> class.
        /// </summary>
        /// <param name="header">DNS record header.</param>
        /// <param name="dataPointer">Pointer to the data portion of the DNS record.</param>
        internal override void Load(DnsRecordHeader header, IntPtr dataPointer)
        {
            base.Load(header, dataPointer);

            Win32DnsAAAARecord record = Marshal.PtrToStructure<Win32DnsAAAARecord>(dataPointer);
            unsafe
            {
                using (var aaaaBuffer = new SafeDnsAAAABuffer(new IntPtr(&record.Ip6Address)))
                {
                    aaaaBuffer.Initialize(IP6_ADDRESS.Size);
                    byte[] ipv6AddressBytes = new byte[IP6_ADDRESS.Size];
                    aaaaBuffer.ReadArray<byte>(0, ipv6AddressBytes, 0, IP6_ADDRESS.Size);
                    this.ipAddress = new IPAddress(ipv6AddressBytes);
                    this.numericIp6Address = new BigInteger(ipv6AddressBytes);
                }
            }
        }

        internal override DnsRecordType RecordType
        {
            get { return DnsRecordType.AAAA; }
        }

        public BigInteger NumericIp6Address
        {
            get { return this.numericIp6Address; }
        }

        public IPAddress IPAddress
        {
            get { return this.ipAddress; }
        }

        [StructLayout(LayoutKind.Explicit, Pack = 8)]
        private unsafe struct IP6_ADDRESS
        {
            public const int Size = 16;

            [FieldOffset(0)]
            public ulong IP6QwordLow;

            [FieldOffset(8)]
            public ulong IP6QwordHigh;
        }

        /// <summary>
        /// Win32DnsAAAARecord - native format AAAA record returned by DNS API (DNS_AAAA_DATA).
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 8)]
        private struct Win32DnsAAAARecord
        {
            /// <summary>Represents the common DNS record header.</summary>
            public DnsRecordHeader Header;

            /// <summary>
            /// IPv6 address of host.
            /// </summary>
            public IP6_ADDRESS Ip6Address;
        }

        public override string ToString() => this.ipAddress.ToString();
    }
}
