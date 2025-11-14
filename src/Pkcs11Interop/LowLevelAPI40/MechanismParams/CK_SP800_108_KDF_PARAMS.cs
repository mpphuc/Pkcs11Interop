/*
 *  Copyright 2012-2025 The Pkcs11Interop Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Written for the Pkcs11Interop project by:
 *  Jaroslav IMRICH <jimrich@jimrich.sk>
 */

using System;
using System.Runtime.InteropServices;
using NativeULong = System.UInt32;

// Note: Code in this file is generated automatically.

namespace Net.Pkcs11Interop.LowLevelAPI40.MechanismParams
{
    /// <summary>
    /// Structure that provides the parameters for the CKM_CLOUDHSM_SP800_108_COUNTER_KDF mechanism
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 0, CharSet = CharSet.Unicode)]
    public struct CK_SP800_108_KDF_PARAMS
    {
        /// <summary>
        /// PRF type (e.g., CKM_SHA256_HMAC, CKM_SHA512_HMAC)
        /// </summary>
        public NativeULong prftype;

        /// <summary>
        /// Number of data parameters
        /// </summary>
        public NativeULong ulNumberOfDataParams;

        /// <summary>
        /// Pointer to array of PRF data parameters
        /// </summary>
        public IntPtr pDataParams;
    }
}

