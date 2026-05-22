using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using OWSData.Models.StoredProcs;
using OWSData.Repositories.Interfaces;
using OWSShared.Interfaces;

namespace OWSPublicAPI.Requests.Users
{
    public class LoginAndCreateSessionRequest : IRequestHandler<LoginAndCreateSessionRequest, IActionResult>, IRequest
    {
        public string Email { get; set; }
        public string Password { get; set; }

        private PlayerLoginAndCreateSession output;
        private Guid customerGUID;
        private IUsersRepository usersRepository;
        private IPublicAPIInputValidation publicAPIInputValidation;

        public void SetData(IUsersRepository usersRepository, IHeaderCustomerGUID customerGuid, IPublicAPIInputValidation publicAPIInputValidation)
        {
            //CustomerGUID = new Guid("56FB0902-6FE7-4BFE-B680-E3C8E497F016");
            this.customerGUID = customerGuid.CustomerGUID;
            this.usersRepository = usersRepository;
            this.publicAPIInputValidation = publicAPIInputValidation;
        }

        public async Task<IActionResult> Handle()
        {
            // Defense-in-depth: reject obviously-malformed emails before paying the DB
            // round-trip. Cheap pre-filter against credential-stuffing scripts that
            // throw garbage at the endpoint. We deliberately do NOT validate password
            // shape here — legacy accounts may have credentials that no longer meet
            // current ValidatePassword rules; that check belongs to RegisterUser only.
            var emailError = publicAPIInputValidation.ValidateEmail(Email);
            if (!string.IsNullOrEmpty(emailError))
            {
                return new OkObjectResult(new PlayerLoginAndCreateSession
                {
                    Authenticated = false,
                    UserSessionGuid = Guid.Empty,
                    ErrorMessage = "Username or Password is invalid!" // generic to avoid email-enumeration
                });
            }

            output = await usersRepository.LoginAndCreateSession(customerGUID, Email, Password, false);

            if (!output.Authenticated || !output.UserSessionGuid.HasValue || output.UserSessionGuid == Guid.Empty)
            {
                output.ErrorMessage = "Username or Password is invalid!";
            }

            return new OkObjectResult(output);
        }
    }
}
