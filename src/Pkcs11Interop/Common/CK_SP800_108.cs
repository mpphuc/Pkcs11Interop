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

// Note: Code in this file is maintained manually.

namespace Net.Pkcs11Interop.Common
{
    /// <summary>
    /// NIST SP 800-108 key derivation function constants
    /// </summary>
    public static class CK_SP800_108
    {
        /// <summary>
        /// PRF data types for SP800-108 KDF
        /// </summary>
        public enum PRF_DATA_TYPE : uint
        {
            /// <summary>
            /// Iteration variable (counter)
            /// </summary>
            CK_SP800_108_ITERATION_VARIABLE = 0x0001,

            /// <summary>
            /// Derived key material length
            /// </summary>
            CK_SP800_108_DKM_LENGTH = 0x0002,

            /// <summary>
            /// Byte array
            /// </summary>
            CK_SP800_108_BYTE_ARRAY = 0x0003,

            /// <summary>
            /// Counter format
            /// </summary>
            SP800_108_COUNTER_FORMAT = 0x0004,

            /// <summary>
            /// PRF label
            /// </summary>
            SP800_108_PRF_LABEL = 0x0005,

            /// <summary>
            /// PRF context
            /// </summary>
            SP800_108_PRF_CONTEXT = 0x0006,

            /// <summary>
            /// Derived key material format
            /// </summary>
            SP800_108_DKM_FORMAT = 0x0007
        }

        /// <summary>
        /// DKM length methods for SP800-108 KDF
        /// </summary>
        public enum DKM_LENGTH_METHOD : uint
        {
            /// <summary>
            /// Sum of keys method
            /// </summary>
            SP800_108_DKM_LENGTH_SUM_OF_KEYS = 1,

            /// <summary>
            /// Sum of segments method
            /// </summary>
            SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS = 2
        }
    }
}

