// Copyright (c) Giorgi Chakhidze
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

namespace DnsQuery;

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
    private IPAddress? ipAddress;

    public DnsAAAARecord()
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
            using var aaaaBuffer = new SafeDnsAAAABuffer(new IntPtr(&record.Ip6Address));
            aaaaBuffer.Initialize(IP6_ADDRESS.Size);
            byte[] ipv6AddressBytes = new byte[IP6_ADDRESS.Size];
            aaaaBuffer.ReadArray<byte>(0, ipv6AddressBytes, 0, IP6_ADDRESS.Size);
            this.ipAddress = GetIPAddressFromIP6_ADDRESS(aaaaBuffer.Read<IP6_ADDRESS>(0));
            this.numericIp6Address = new BigInteger(ipv6AddressBytes);
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

    public IPAddress? IPAddress
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

        [FieldOffset(0)]
        public uint Ip6Address0;

        [FieldOffset(4)]
        public uint Ip6Address1;

        [FieldOffset(8)]
        public uint Ip6Address2;

        [FieldOffset(12)]
        public uint Ip6Address3;
    }

    private static IPAddress GetIPAddressFromIP6_ADDRESS(IP6_ADDRESS data)
    {
        var addressBytes = new byte[16];
        addressBytes[0] = (byte)(data.Ip6Address0 & 0x000000FF);
        addressBytes[1] = (byte)((data.Ip6Address0 & 0x0000FF00) >> 8);
        addressBytes[2] = (byte)((data.Ip6Address0 & 0x00FF0000) >> 16);
        addressBytes[3] = (byte)((data.Ip6Address0 & 0xFF000000) >> 24);
        addressBytes[4] = (byte)(data.Ip6Address1 & 0x000000FF);
        addressBytes[5] = (byte)((data.Ip6Address1 & 0x0000FF00) >> 8);
        addressBytes[6] = (byte)((data.Ip6Address1 & 0x00FF0000) >> 16);
        addressBytes[7] = (byte)((data.Ip6Address1 & 0xFF000000) >> 24);
        addressBytes[8] = (byte)(data.Ip6Address2 & 0x000000FF);
        addressBytes[9] = (byte)((data.Ip6Address2 & 0x0000FF00) >> 8);
        addressBytes[10] = (byte)((data.Ip6Address2 & 0x00FF0000) >> 16);
        addressBytes[11] = (byte)((data.Ip6Address2 & 0xFF000000) >> 24);
        addressBytes[12] = (byte)(data.Ip6Address3 & 0x000000FF);
        addressBytes[13] = (byte)((data.Ip6Address3 & 0x0000FF00) >> 8);
        addressBytes[14] = (byte)((data.Ip6Address3 & 0x00FF0000) >> 16);
        addressBytes[15] = (byte)((data.Ip6Address3 & 0xFF000000) >> 24);

        return new IPAddress(addressBytes);
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

    public override string ToString() => this.ipAddress?.ToString() ?? "(null)";
}
