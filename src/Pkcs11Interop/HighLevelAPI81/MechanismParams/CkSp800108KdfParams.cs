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
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI.MechanismParams;
using Net.Pkcs11Interop.LowLevelAPI81.MechanismParams;
using NativeULong = System.UInt64;

// Note: Code in this file is maintained manually.

namespace Net.Pkcs11Interop.HighLevelAPI81.MechanismParams
{
    /// <summary>
    /// Parameters for the CKM_CLOUDHSM_SP800_108_COUNTER_KDF mechanism
    /// </summary>
    public class CkSp800108KdfParams : ICkSp800108KdfParams
    {
        /// <summary>
        /// Flag indicating whether instance has been disposed
        /// </summary>
        private bool _disposed = false;

        /// <summary>
        /// Low level mechanism parameters
        /// </summary>
        private CK_SP800_108_KDF_PARAMS _lowLevelStruct = new CK_SP800_108_KDF_PARAMS();

        /// <summary>
        /// Pointer to allocated array of PRF data parameters
        /// </summary>
        private IntPtr _dataParamsArrayPtr = IntPtr.Zero;

        /// <summary>
        /// List of pointers to allocated value memory (for cleanup)
        /// </summary>
        private List<IntPtr> _allocatedValuePtrs = new List<IntPtr>();

        /// <summary>
        /// Initializes a new instance of the CkSp800108KdfParams class.
        /// </summary>
        /// <param name='prftype'>PRF type (e.g., CKM_SHA256_HMAC, CKM_SHA512_HMAC)</param>
        /// <param name='dataParams'>List of PRF data parameters</param>
        public CkSp800108KdfParams(CKM prftype, List<ISp800108PrfDataParam> dataParams)
        {
            if (dataParams == null || dataParams.Count == 0)
                throw new ArgumentException("dataParams cannot be null or empty", "dataParams");

            _lowLevelStruct.prftype = ConvertUtils.UInt64FromCKM(prftype);
            _lowLevelStruct.ulNumberOfDataParams = ConvertUtils.UInt64FromInt32(dataParams.Count);
            _lowLevelStruct.pDataParams = IntPtr.Zero;

            // Calculate size of one CK_PRF_DATA_PARAM structure
            int structSize = Marshal.SizeOf(typeof(CK_PRF_DATA_PARAM));

            // Allocate memory for the array of CK_PRF_DATA_PARAM structures
            _dataParamsArrayPtr = UnmanagedMemory.Allocate(structSize * dataParams.Count);

            // Copy each data parameter structure to unmanaged memory
            IntPtr currentPtr = _dataParamsArrayPtr;
            foreach (var dataParam in dataParams)
            {
                CK_PRF_DATA_PARAM param = new CK_PRF_DATA_PARAM();
                param.type = (NativeULong)dataParam.Type;
                param.pValue = IntPtr.Zero;
                param.ulValueLen = 0;

                // If value is provided, allocate memory and copy it
                if (dataParam.Value != null && dataParam.Value.Length > 0)
                {
                    IntPtr valuePtr = UnmanagedMemory.Allocate(dataParam.Value.Length);
                    UnmanagedMemory.Write(valuePtr, dataParam.Value);
                    _allocatedValuePtrs.Add(valuePtr);
                    param.pValue = valuePtr;
                    param.ulValueLen = ConvertUtils.UInt64FromInt32(dataParam.Value.Length);
                }

                // Copy structure to unmanaged memory
                Marshal.StructureToPtr(param, currentPtr, false);
                currentPtr = new IntPtr(currentPtr.ToInt64() + structSize);
            }

            _lowLevelStruct.pDataParams = _dataParamsArrayPtr;
        }

        #region IMechanismParams

        /// <summary>
        /// Returns managed object that can be marshaled to an unmanaged block of memory
        /// </summary>
        /// <returns>A managed object holding the data to be marshaled. This object must be an instance of a formatted class.</returns>
        public object ToMarshalableStructure()
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            return _lowLevelStruct;
        }

        #endregion

        #region IDisposable

        /// <summary>
        /// Disposes object
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes object
        /// </summary>
        /// <param name="disposing">Flag indicating whether managed resources should be disposed</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!this._disposed)
            {
                if (disposing)
                {
                    // Dispose managed objects
                    _allocatedValuePtrs.Clear();
                }

                // Dispose unmanaged objects
                // Free all allocated value pointers
                foreach (IntPtr ptr in _allocatedValuePtrs)
                {
                    IntPtr ptrToFree = ptr;
                    UnmanagedMemory.Free(ref ptrToFree);
                }
                _allocatedValuePtrs.Clear();

                // Free the array of structures
                UnmanagedMemory.Free(ref _dataParamsArrayPtr);
                _lowLevelStruct.pDataParams = IntPtr.Zero;
                _lowLevelStruct.ulNumberOfDataParams = 0;

                _disposed = true;
            }
        }

        /// <summary>
        /// Class destructor that disposes object if caller forgot to do so
        /// </summary>
        ~CkSp800108KdfParams()
        {
            Dispose(false);
        }

        #endregion
    }
}

