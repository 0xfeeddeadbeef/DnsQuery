﻿/*
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

namespace DnsQuery;

using System;
using System.Runtime.InteropServices;

/// <summary>
///  Represents the native format of a DNS record returned by the Win32 DNS API
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct DnsRecordHeader
{
    /// <summary>
    /// Pointer to the next DNS dnsRecord.
    /// </summary>
    internal IntPtr NextRecord;

    /// <summary>
    /// Domain name of the dnsRecord set to be updated.
    /// </summary>
    internal string Name;

    /// <summary>The type of the current dnsRecord.</summary>
    internal DnsRecordType RecordType;

    /// <summary>Length of the data, in bytes. </summary>
    internal ushort DataLength;

    /// <summary>
    /// Flags used in the structure, in the form of a bit-wise DWORD.
    /// </summary>
    internal uint Flags;

    /// <summary>
    /// Time to live, in seconds
    /// </summary>
    internal uint Ttl;

    /// <summary>
    /// Reserved for future use.
    /// </summary>
    internal uint Reserved;

    internal static readonly int SizeOf = Marshal.SizeOf<DnsRecordHeader>();
}
