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
using System.Runtime.InteropServices;

/// <summary>
/// Represents a DNS A Record.
/// </summary>
public sealed class DnsARecord : DnsRecord
{
    private uint numericIpAddress;
    private IPAddress? ipAddress;

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

    public IPAddress? IPAddress
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
        public uint IpAddress;
    }

    public override string ToString() => this.ipAddress?.ToString() ?? "(null)";
}
