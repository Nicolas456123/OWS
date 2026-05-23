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
    /// Shared validation rules for the Ability endpoints. Centralised so add/update/remove
    /// keep the same shape (otherwise the strictest endpoint becomes a guard the others
    /// silently bypass — classic gap exploit).
    /// </summary>
    internal static class AbilityRequestLimits
    {
        public const int MaxNameLength = 128;
        public const int MaxAbilityLevel = 1000;       // far above any realistic game cap
        public const int MaxCustomJsonLength = 64 * 1024; // 64 KB

        public static bool IsValid(string abilityName, string characterName, int abilityLevel, string customJson)
        {
            if (string.IsNullOrWhiteSpace(abilityName) || abilityName.Length > MaxNameLength) return false;
            if (string.IsNullOrWhiteSpace(characterName) || characterName.Length > MaxNameLength) return false;
            if (abilityLevel < 0 || abilityLevel > MaxAbilityLevel) return false;
            if (customJson != null && customJson.Length > MaxCustomJsonLength) return false;
            return true;
        }
    }

    /// <summary>
    /// Add Ability To Character
    /// </summary>
    /// <remarks>
    /// Adds an Ability to a Character and also sets the initial values of Ability Level and the per instance Custom JSON
    /// </remarks>
    public class AddAbilityToCharacterRequest
    {
        /// <summary>
        /// Ability Name
        /// </summary>
        /// <remarks>
        /// This is the name of the ability to add to the character.
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
        /// This is the name of the character to add the ability to.
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

            // Validate before touching the DB. Without these caps a single client could
            // push a 100 MB CustomJSON per call (no schema enforcement at the SQL layer)
            // or store an AbilityLevel of int.MinValue (gameplay arithmetic underflow).
            if (!AbilityRequestLimits.IsValid(AbilityName, CharacterName, AbilityLevel, CharHasAbilitiesCustomJSON))
            {
                Log.Warning("AddAbilityToCharacter rejected (Customer={Customer}, AbilityName.Len={AbilityLen}, CharName.Len={CharLen}, Level={Level}, CustomJson.Len={JsonLen})",
                    customerGUID,
                    AbilityName?.Length ?? 0,
                    CharacterName?.Length ?? 0,
                    AbilityLevel,
                    CharHasAbilitiesCustomJSON?.Length ?? 0);
                output.Success = false;
                output.ErrorMessage = "Invalid ability request.";
                return output;
            }

            await charactersRepository.AddAbilityToCharacter(customerGUID, AbilityName, CharacterName, AbilityLevel, CharHasAbilitiesCustomJSON);

            output.Success = true;
            output.ErrorMessage = "";

            return output;
        }
    }
}
