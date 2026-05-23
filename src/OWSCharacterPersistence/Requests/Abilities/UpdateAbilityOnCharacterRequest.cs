using OWSData.Models.Composites;
using OWSData.Repositories.Interfaces;
using OWSShared.Interfaces;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OWSCharacterPersistence.Requests.Abilities
{
    /// <summary>
    /// Update Ability on Character
    /// </summary>
    /// <remarks>
    /// Update the Ability on the Character to modify Ability Level and the per instance Custom JSON
    /// </remarks>
    public class UpdateAbilityOnCharacterRequest
    {
        /// <summary>
        /// Ability Name
        /// </summary>
        /// <remarks>
        /// This is the name of the ability to update on the character.
        /// </remarks>
        public string AbilityName { get; set; }
        /// <summary>
        /// Ability Level
        /// </summary>
        /// <remarks>
        /// This is a number representing the Ability Level of the ability to add.  If you need more per instance customization, use the Custom JSON field.
        /// </remarks>
        public int AbilityLevel { get; set; }
        /// <summary>
        /// Character Name
        /// </summary>
        /// <remarks>
        /// This is the name of the character to update the ability on.
        /// </remarks>
        public string CharacterName { get; set; }
        /// <summary>
        /// Custom JSON
        /// </summary>
        /// <remarks>
        /// This field is used to store Custom JSON for the specific instance of this Ability.  If you have a system where each ability on a character has some kind of custom variation, then this is where to store that variation data.  In a system where an ability operates the same on every player, this field would not be used.  Don't store Ability Level in this field, as there is already a field for that.  If you need to store Custom JSON for ALL instances of an ability, use the Custom JSON on the Ability itself.
        /// </remarks>
        public string CharHasAbilitiesCustomJSON { get; set; }

        private SuccessAndErrorMessage output;
        private Guid customerGUID;
        private ICharactersRepository charactersRepository;

        public void SetData(ICharactersRepository charactersRepository, IHeaderCustomerGUID customerGuid)
        {
            this.charactersRepository = charactersRepository;
            customerGUID = customerGuid.CustomerGUID;
        }

        public async Task<SuccessAndErrorMessage> Handle()
        {
            output = new SuccessAndErrorMessage();

            // Same caps as AddAbilityToCharacter — keep them in lockstep so an attacker
            // can't switch endpoints to bypass the stricter one (see AbilityRequestLimits).
            if (!AbilityRequestLimits.IsValid(AbilityName, CharacterName, AbilityLevel, CharHasAbilitiesCustomJSON))
            {
                Log.Warning("UpdateAbilityOnCharacter rejected (Customer={Customer}, AbilityName.Len={AbilityLen}, CharName.Len={CharLen}, Level={Level}, CustomJson.Len={JsonLen})",
                    customerGUID,
                    AbilityName?.Length ?? 0,
                    CharacterName?.Length ?? 0,
                    AbilityLevel,
                    CharHasAbilitiesCustomJSON?.Length ?? 0);
                output.Success = false;
                output.ErrorMessage = "Invalid ability request.";
                return output;
            }

            await charactersRepository.UpdateAbilityOnCharacter(customerGUID, AbilityName, CharacterName, AbilityLevel, CharHasAbilitiesCustomJSON);

            output.Success = true;
            output.ErrorMessage = "";

            return output;
        }
    }
}
