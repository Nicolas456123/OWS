using Microsoft.AspNetCore.Mvc;
using OWSData.Models.Composites;
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
    public class UpdateCharacterStatsRequest
    {
        public UpdateCharacterStats updateCharacterStats { get; set; }

        private Guid customerGUID;
        private ICharactersRepository charactersRepository;

        public void SetData(ICharactersRepository charactersRepository, IHeaderCustomerGUID customerGuid)
        {
            this.charactersRepository = charactersRepository;
            customerGUID = customerGuid.CustomerGUID;
        }

        public async Task<SuccessAndErrorMessage> Handle()
        {
            SuccessAndErrorMessage successAndErrorMessage = new SuccessAndErrorMessage();
            successAndErrorMessage.Success = true;

            try
            {
                await charactersRepository.UpdateCharacterStats(updateCharacterStats);
            }
            catch (Exception ex)
            {
                // Server-side full detail (stack trace, SQL error), client-side generic
                // message. Returning ex.Message would leak DB column names, constraint
                // violations and stored-proc internals over the wire.
                Log.Error(ex, "UpdateCharacterStats failed");
                successAndErrorMessage.ErrorMessage = "An internal error occurred. Please try again later.";
                successAndErrorMessage.Success = false;
            }

            return successAndErrorMessage;
        }
    }
}
