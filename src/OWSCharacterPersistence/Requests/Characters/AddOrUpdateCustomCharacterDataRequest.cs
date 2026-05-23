using OWSData.Models.StoredProcs;
using OWSData.Repositories.Interfaces;
using OWSShared.Interfaces;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OWSCharacterPersistence.Requests.Characters
{
    public class AddOrUpdateCustomDataRequest
    {
        // Size caps. Custom character data is BLOB-ish JSON the client uses for save state
        // (inventory snapshots, quest progress). 64 KB per field is generous for any reasonable
        // payload; without a cap, a single client could push multi-megabyte rows on every save
        // and saturate the row-cache or fill the database disk.
        // Field name is the column key — 128 chars matches a typical varchar limit and avoids
        // accidental DoS by 1 MB column names.
        private const int MaxFieldNameLength = 128;
        private const int MaxFieldValueLength = 64 * 1024; // 64 KB

        public AddOrUpdateCustomCharacterData addOrUpdateCustomCharacterData { get; set; }

        private Guid customerGUID;
        private ICharactersRepository charactersRepository;

        public void SetData(ICharactersRepository charactersRepository, IHeaderCustomerGUID customerGuid)
        {
            this.charactersRepository = charactersRepository;
            customerGUID = customerGuid.CustomerGUID;
        }

        public async Task Handle()
        {
            // Defense in depth: cap field name + value size before hitting the DB. A 10 MB
            // FieldValue is almost certainly garbage / a bug / an attempted DoS, never a
            // legitimate write. Drop silently with a Warning so the offender's pattern shows
            // up in logs without giving them feedback to tune their attack.
            if (addOrUpdateCustomCharacterData == null ||
                string.IsNullOrWhiteSpace(addOrUpdateCustomCharacterData.CustomFieldName) ||
                addOrUpdateCustomCharacterData.CustomFieldName.Length > MaxFieldNameLength ||
                (addOrUpdateCustomCharacterData.FieldValue != null &&
                 addOrUpdateCustomCharacterData.FieldValue.Length > MaxFieldValueLength))
            {
                Log.Warning(
                    "AddOrUpdateCustomCharacterData rejected: oversized or missing fields (NameLen={NameLen}, ValueLen={ValueLen}, Customer={Customer})",
                    addOrUpdateCustomCharacterData?.CustomFieldName?.Length ?? 0,
                    addOrUpdateCustomCharacterData?.FieldValue?.Length ?? 0,
                    customerGUID);
                return;
            }

            await charactersRepository.AddOrUpdateCustomCharacterData(customerGUID, addOrUpdateCustomCharacterData);

            return;
        }
    }
}
