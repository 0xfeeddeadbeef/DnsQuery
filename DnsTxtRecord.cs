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
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Runtime.InteropServices;

public sealed class DnsTxtRecord : DnsRecord
{
    private static ReadOnlyCollection<string>? s_Empty;
    private static ReadOnlyCollection<string> Empty
    {
        get { return s_Empty ??= new ReadOnlyCollection<string>([]); }
    }

    private ReadOnlyCollection<string>? txtEntries;

    public DnsTxtRecord()
    {
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Win32DnsTxtRecord
    {
        /// <summary>Represents the common DNS record header.</summary>
        public DnsRecordHeader Header;

        public uint StringCount;

        //
        // After research, it appears that ANYSIZE_ARRAY marshalling is not implemented.
        // Must use pointer and Marshal.Offsetof/Read* methods -OR- SafeBuffer class!
        // See: https://connect.microsoft.com/VisualStudio/feedback/details/1138788/marshalasattribute-class-does-not-permits-marshalling-of-struct-with-array-defined-as-anysize-array
        //
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1, ArraySubType = UnmanagedType.SysUInt)]
        public IntPtr[] StringArray;
    }

    private sealed class SafeDnsTxtBuffer : SafeBuffer
    {
        public SafeDnsTxtBuffer(IntPtr address)
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

    internal override DnsRecordType RecordType
    {
        get { return DnsRecordType.TXT; }
    }

    public IReadOnlyCollection<string>? TextEntries
    {
        get { return this.txtEntries; }
    }

    internal override void Load(DnsRecordHeader header, IntPtr dataPointer)
    {
        base.Load(header, dataPointer);

        Win32DnsTxtRecord record = Marshal.PtrToStructure<Win32DnsTxtRecord>(dataPointer);

        if (record.StringCount > 0)
        {
            var txtRecords = new List<string>((int)record.StringCount);
            var stringPtrs = new IntPtr[record.StringCount];
            var txtArrayAddr = new IntPtr(dataPointer.ToInt64() + Marshal.OffsetOf<Win32DnsTxtRecord>(nameof(Win32DnsTxtRecord.StringArray)).ToInt64());

            using (var txtBuffer = new SafeDnsTxtBuffer(txtArrayAddr))
            {
                txtBuffer.Initialize<IntPtr>(record.StringCount);
                txtBuffer.ReadArray(0, stringPtrs, 0, stringPtrs.Length);
            }

            for (int i = 0; i < stringPtrs.Length; i++)
            {
                txtRecords.Add(Marshal.PtrToStringUni(stringPtrs[i]));
            }

            this.txtEntries = new ReadOnlyCollection<string>(txtRecords);
        }
        else
        {
            this.txtEntries = Empty;
        }
    }

    /*
    public override string ToString()
    {
        if (this.txtEntries != null && this.txtEntries.Count > 0)
        {
            return "TXT.StringArray=\"" + string.Join("; ", this.txtEntries) + "\"";
        }

        return "TXT.StringArray=\"(empty)\"";
    }
    */
}
