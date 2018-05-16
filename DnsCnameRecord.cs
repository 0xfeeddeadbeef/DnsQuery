// -----------------------------------------------------------------------------------------------------------
// <copyright file="DnsCnameRecord.cs" company="">
// Copyright © 2017 Giorgi Chakhidze. All rights reserved.
// </copyright>
// <author>Giorgi Chakhidze</author>
// <email>0xfeeddeadbeef@gmail.com</email>
// <date>Thursday, October 12, 2017 6:03:51 PM</date>
// <summary>Contains the DnsCnameRecord class.</summary>
// -----------------------------------------------------------------------------------------------------------

namespace DnsQuery
{
    using System;
    using System.Runtime.InteropServices;

    public sealed class DnsCnameRecord : DnsRecord
    {
        private string nameHost;

        public DnsCnameRecord()
        {
        }

        internal override DnsRecordType RecordType
        {
            get { return DnsRecordType.CNAME; }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct Win32DnsCnameRecord
        {
            /// <summary>Represents the common DNS record header.</summary>
            public DnsRecordHeader Header;

            public string NameHost;
        }

        internal override void Load(DnsRecordHeader header, IntPtr dataPointer)
        {
            base.Load(header, dataPointer);

            Win32DnsCnameRecord record = Marshal.PtrToStructure<Win32DnsCnameRecord>(dataPointer);
            this.nameHost = record.NameHost;
        }

        public string NameHost
        {
            get { return this.nameHost; }
        }

        public override string ToString() => this.nameHost;
    }
}
