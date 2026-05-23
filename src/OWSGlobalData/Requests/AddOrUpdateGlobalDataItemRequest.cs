using Microsoft.AspNetCore.Mvc;
using OWSData.Models.Composites;
using OWSData.Models.Tables;
using OWSData.Repositories.Interfaces;
using OWSGlobalData.DTOs;
using OWSShared.Interfaces;
using Serilog;
using System;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace OWSGlobalData.Requests
{
    public class AddOrUpdateGlobalDataItemRequest
    {
        // Caps + format.
        // - Key is identifier-ish (typically GameInstance or settings name): 256 chars covers
        //   any sane convention while bounding the column. The regex (alphanumeric + -._)
        //   matches what OWSPlugin's GetGlobalDataItem now sends URL-encoded, and rejects
        //   path/query/JSON injection vectors that would have weaponized the value column
        //   into a side-channel for arbitrary HTTP routing.
        // - Value is application-defined JSON / blob — 1 MB is enough for serialized world
        //   state without enabling a multi-megabyte spam vector. The whole table sits in
        //   memory cache; one rogue caller filling it with 100 MB rows is enough to OOM.
        private const int MaxKeyLength = 256;
        private const int MaxValueLength = 1024 * 1024; // 1 MB
        private static readonly Regex KeyAllowedChars = new Regex(@"^[A-Za-z0-9_\-\.]+$", RegexOptions.Compiled);

        private readonly AddOrUpdateGlobalDataItemDTO _dto;
        private readonly Guid _CustomerGUID;
        private readonly IGlobalDataRepository _globalDataRepository;

        public AddOrUpdateGlobalDataItemRequest(AddOrUpdateGlobalDataItemDTO dto, IGlobalDataRepository globalDataRepository, IHeaderCustomerGUID headerCustomerGUID)
        {
            _dto = dto;
            _globalDataRepository = globalDataRepository;
            _CustomerGUID = headerCustomerGUID.CustomerGUID;
        }

        public async Task<SuccessAndErrorMessage> Handle()
        {
            if (_dto == null ||
                string.IsNullOrWhiteSpace(_dto.GlobalDataKey) ||
                _dto.GlobalDataKey.Length > MaxKeyLength ||
                !KeyAllowedChars.IsMatch(_dto.GlobalDataKey) ||
                (_dto.GlobalDataValue != null && _dto.GlobalDataValue.Length > MaxValueLength))
            {
                // Generic message — never leak which check failed (key shape vs value size).
                // An attacker probing the boundary should learn nothing from the response.
                Log.Warning(
                    "AddOrUpdateGlobalDataItem rejected (KeyLen={KeyLen}, ValueLen={ValueLen}, Customer={Customer})",
                    _dto?.GlobalDataKey?.Length ?? 0,
                    _dto?.GlobalDataValue?.Length ?? 0,
                    _CustomerGUID);
                return new SuccessAndErrorMessage { Success = false, ErrorMessage = "Invalid global data item." };
            }

            var globalDataToAdd = new GlobalData() {
                CustomerGuid = _CustomerGUID,
                GlobalDataKey = _dto.GlobalDataKey,
                GlobalDataValue = _dto.GlobalDataValue
            };

            try
            {
                await _globalDataRepository.AddOrUpdateGlobalData(globalDataToAdd);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "AddOrUpdateGlobalData failed");
                return new SuccessAndErrorMessage { Success = false, ErrorMessage = "An internal error occurred." };
            }

            return new SuccessAndErrorMessage { Success = true, ErrorMessage = "" };
        }
    }
}
