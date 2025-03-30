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
using System.Runtime.InteropServices;

public sealed class DnsSoaRecord : DnsRecord
{
    private string? primaryNameServer;
    private string? administratorName;
    private uint serialNumber;
    private uint refresh;
    private uint retry;
    private uint expire;
    private uint defaultTtl;

    public DnsSoaRecord()
    {
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Win32DnsSoaRecord
    {
        /// <summary>Represents the common DNS record header.</summary>
        public DnsRecordHeader Header;

        public string NamePrimaryServer;
        public string NameAdministrator;
        public uint SerialNo;
        public uint Refresh;
        public uint Retry;
        public uint Expire;
        public uint DefaultTtl;
    }

    internal override DnsRecordType RecordType
    {
        get { return DnsRecordType.SOA; }
    }

    public string? PrimaryNameServer
    {
        get { return this.primaryNameServer; }
    }

    public string? AdministratorName
    {
        get { return this.administratorName; }
    }

    public uint SerialNumber
    {
        get { return this.serialNumber; }
    }

    public uint Refresh
    {
        get { return this.refresh; }
    }

    public uint Retry
    {
        get { return this.retry; }
    }

    public uint Expire
    {
        get { return this.expire; }
    }

    public uint DefaultTtl
    {
        get { return this.defaultTtl; }
    }

    internal override void Load(DnsRecordHeader header, IntPtr dataPointer)
    {
        base.Load(header, dataPointer);

        Win32DnsSoaRecord record = Marshal.PtrToStructure<Win32DnsSoaRecord>(dataPointer);
        this.primaryNameServer = record.NamePrimaryServer;
        this.administratorName = record.NameAdministrator;
        this.serialNumber = record.SerialNo;
        this.refresh = record.Refresh;
        this.retry = record.Retry;
        this.expire = record.Expire;
        this.defaultTtl = record.DefaultTtl;
    }
}
