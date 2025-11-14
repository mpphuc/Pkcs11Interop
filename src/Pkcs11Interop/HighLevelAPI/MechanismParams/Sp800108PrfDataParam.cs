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
using Net.Pkcs11Interop.Common;

// Note: Code in this file is maintained manually.

namespace Net.Pkcs11Interop.HighLevelAPI.MechanismParams
{
    /// <summary>
    /// Represents a PRF data parameter for SP800-108 KDF
    /// This is a simple data class that can be used across all API versions.
    /// </summary>
    public class Sp800108PrfDataParam : ISp800108PrfDataParam
    {
        /// <summary>
        /// Type of PRF data (CK_SP800_108_ITERATION_VARIABLE, SP800_108_PRF_LABEL, etc.)
        /// </summary>
        public CK_SP800_108.PRF_DATA_TYPE Type { get; set; }

        /// <summary>
        /// Value bytes (null if not applicable for this type)
        /// </summary>
        public byte[] Value { get; set; }
    }
}

