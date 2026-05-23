using Microsoft.AspNetCore.Mvc;
using OWSData.Models.Composites;
using OWSData.Repositories.Interfaces;
using OWSShared.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OWSPublicAPI.Requests.Users
{
    /// <summary>
    /// RemoveCharacterRequest Handler
    /// </summary>
    /// <remarks>
    /// Handles api/Users/RemoveCharacter requests.
    /// </remarks>
    public class RemoveCharacterRequest
    {
        /// <summary>
        /// UserSessionGUID Request Paramater.
        /// </summary>
        /// <remarks>
        /// Contains the User Session GUID from the request.  This identifies the User we are modifying.
        /// </remarks>
        public Guid UserSessionGUID { get; set; }
        /// <summary>
        /// CharacterName Request Paramater.
        /// </summary>
        /// <remarks>
        /// Contains the Character Name from the request.  This is the new Character Name to create.
        /// </remarks>
        public string CharacterName { get; set; }

        private Guid CustomerGUID;
        private IUsersRepository usersRepository;
        private IPublicAPIInputValidation publicAPIInputValidation;

        /// <summary>
        /// Set Dependencies for CreateCharacterRequest
        /// </summary>
        /// <remarks>
        /// Injects the dependencies for the CreateCharacterRequest.
        /// </remarks>
        public void SetData(IUsersRepository usersRepository, IPublicAPIInputValidation publicAPIInputValidation, IHeaderCustomerGUID customerGuid)
        {
            CustomerGUID = customerGuid.CustomerGUID;
            this.usersRepository = usersRepository;
            // Same validation surface as CreateCharacterRequest. Without this wire, the
            // delete path used to accept any string — including empty, oversized, or
            // exotic-charset names — letting a caller probe for character existence
            // (and possibly trip the repo's "not found" path in suggestive ways).
            this.publicAPIInputValidation = publicAPIInputValidation;
        }

        /// <summary>
        /// Handles the CreateCharacterRequest
        /// </summary>
        /// <remarks>
        /// Overrides IRequestHandler Handle().
        /// </remarks>
        public async Task<IActionResult> Handle()
        {
            // Reuse the project-wide character-name validator. Returns a non-empty message
            // when the name violates length/charset rules; surface it as a generic failure
            // (the validator's message is already user-safe).
            var nameError = publicAPIInputValidation.ValidateCharacterName(CharacterName);
            if (!string.IsNullOrEmpty(nameError))
            {
                return new OkObjectResult(new SuccessAndErrorMessage
                {
                    Success = false,
                    ErrorMessage = nameError
                });
            }

            SuccessAndErrorMessage output = await usersRepository.RemoveCharacter(CustomerGUID, UserSessionGUID, CharacterName);

            return new OkObjectResult(output);
        }
    }
}
