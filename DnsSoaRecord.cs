// -----------------------------------------------------------------------------------------------------------
// <copyright file="DnsSoaRecord.cs" company="">
// Copyright © 2017 Giorgi Chakhidze. All rights reserved.
// </copyright>
// <author>Giorgi Chakhidze</author>
// <email>0xfeeddeadbeef@gmail.com</email>
// <date>Thursday, October 12, 2017 5:58:03 PM</date>
// <summary>Contains the DnsSoaRecord class.</summary>
// -----------------------------------------------------------------------------------------------------------

namespace DnsQuery
{
    using System;
    using System.Runtime.InteropServices;

    public sealed class DnsSoaRecord : DnsRecord
    {
        private string primaryNameServer;
        private string administratorName;
        private UInt32 serialNumber;
        private UInt32 refresh;
        private UInt32 retry;
        private UInt32 expire;
        private UInt32 defaultTtl;

        private DnsSoaRecord()
        {
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct Win32DnsSoaRecord
        {
            /// <summary>Represents the common DNS record header.</summary>
            public DnsRecordHeader Header;

            public string NamePrimaryServer;
            public string NameAdministrator;
            public UInt32 SerialNo;
            public UInt32 Refresh;
            public UInt32 Retry;
            public UInt32 Expire;
            public UInt32 DefaultTtl;
        }

        internal override DnsRecordType RecordType
        {
            get { return DnsRecordType.SOA; }
        }

        public string PrimaryNameServer
        {
            get { return this.primaryNameServer; }
        }

        public string AdministratorName
        {
            get { return this.administratorName; }
        }

        public UInt32 SerialNumber
        {
            get { return this.serialNumber; }
        }

        public UInt32 Refresh
        {
            get { return this.refresh; }
        }

        public UInt32 Retry
        {
            get { return this.retry; }
        }

        public UInt32 Expire
        {
            get { return this.expire; }
        }

        public UInt32 DefaultTtl
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
}
