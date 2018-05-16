// -----------------------------------------------------------------------------------------------------------
// <copyright file="DnsPtrRecord.cs" company="">
// Copyright © 2017 Giorgi Chakhidze. All rights reserved.
// </copyright>
// <author>Giorgi Chakhidze</author>
// <email>0xfeeddeadbeef@gmail.com</email>
// <date>Thursday, October 12, 2017 5:28:51 PM</date>
// <summary>Contains the DnsPtrRecord class.</summary>
// -----------------------------------------------------------------------------------------------------------

namespace DnsQuery
{
    using System;
    using System.Runtime.InteropServices;

    public sealed class DnsPtrRecord : DnsRecord
    {
        private string nameHost;

        private DnsPtrRecord()
        {
        }

        internal override void Load(DnsRecordHeader header, IntPtr dataPointer)
        {
            base.Load(header, dataPointer);

            Win32DnsPtrRecord record = Marshal.PtrToStructure<Win32DnsPtrRecord>(dataPointer);
            this.nameHost = record.NameHost;
        }

        internal override DnsRecordType RecordType
        {
            get { return DnsRecordType.PTR; }
        }

        public string NameHost
        {
            get { return this.nameHost; }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct Win32DnsPtrRecord
        {
            /// <summary>Represents the common DNS record header.</summary>
            public DnsRecordHeader Header;

            public string NameHost;
        }

        public override string ToString() => this.nameHost;
    }
}
