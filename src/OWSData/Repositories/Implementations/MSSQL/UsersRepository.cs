using Dapper;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using Npgsql;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using OWSData.Models;
using OWSData.Models.Composites;
using OWSData.Models.StoredProcs;
using OWSData.Models.Tables;
using OWSData.Repositories.Interfaces;
using OWSData.SQL;
using OWSShared.Options;
using Serilog;

namespace OWSData.Repositories.Implementations.MSSQL
{
    public class UsersRepository : IUsersRepository
    {
        private readonly IOptions<StorageOptions> _storageOptions;

        public UsersRepository(IOptions<StorageOptions> storageOptions)
        {
            _storageOptions = storageOptions;
        }

        public IDbConnection Connection
        {
            get
            {
                return new SqlConnection(_storageOptions.Value.OWSDBConnectionString);
            }
        }

        public async Task<IEnumerable<GetAllCharacters>> GetAllCharacters(Guid customerGUID, Guid userSessionGUID)
        {
            IEnumerable<GetAllCharacters> outputObject = new List<GetAllCharacters>();

            using (var conn = Connection)
            {
                var p = new DynamicParameters();
                p.Add("CustomerGUID", customerGUID);
                p.Add("UserSessionGUID", userSessionGUID);

                outputObject = await conn.QueryAsync<GetAllCharacters>(GenericQueries.GetAllCharacters,
                p,
                commandType: CommandType.Text);
            }

            return outputObject;
        }

        public async Task<CreateCharacter> CreateCharacter(Guid customerGUID, Guid userSessionGUID, string characterName, string className)
        {
            CreateCharacter outputObject = new CreateCharacter();

            try
            {
                using (var conn = Connection)
                {
                    var p = new DynamicParameters();
                    p.Add("CustomerGUID", customerGUID);
                    p.Add("UserSessionGUID", userSessionGUID);
                    p.Add("CharacterName", characterName);
                    p.Add("ClassName", className);
                    p.Add("ErrorMessage", dbType: DbType.String, direction: ParameterDirection.Output, size: 50);

                    outputObject = await conn.QuerySingleAsync<CreateCharacter>("AddCharacter",
                    p,
                    commandType: CommandType.StoredProcedure);
                }

                if (String.IsNullOrEmpty(outputObject.ErrorMessage))
                {
                    outputObject.Success = true;
                }
                else
                {
                    outputObject.Success = false;
                }

                return outputObject;
            }
            catch (Exception ex)
            {
                outputObject.Success = false;
                outputObject.ErrorMessage = "An internal error occurred. Please try again later.";
                Log.Error(ex, "CreateCharacter failed");

                return outputObject;
            }
        }

        public async Task<SuccessAndErrorMessage> CreateCharacterUsingDefaultCharacterValues(Guid customerGUID, Guid userGUID, string characterName, string defaultSetName)
        {
            SuccessAndErrorMessage outputObject = new SuccessAndErrorMessage();

            IDbConnection conn = Connection;
            conn.Open();
            using IDbTransaction transaction = conn.BeginTransaction();
            try
            {
                    var parameters = new DynamicParameters();
                    parameters.Add("CustomerGUID", customerGUID);
                    parameters.Add("UserGUID", userGUID);
                    parameters.Add("CharacterName", characterName);
                    parameters.Add("DefaultSetName", defaultSetName);

                    int outputCharacterId = await conn.QuerySingleOrDefaultAsync<int>(MSSQLQueries.AddCharacterUsingDefaultCharacterValues,
                        parameters,
                    commandType: CommandType.Text,
                    transaction: transaction);

                    parameters.Add("CharacterID", outputCharacterId);
                    await conn.ExecuteAsync(GenericQueries.AddDefaultCustomCharacterData,
                        parameters,
                        commandType: CommandType.Text,
                        transaction: transaction);
                    transaction.Commit();
            }
            catch (Exception ex)
            {
                transaction.Rollback();
                Log.Error(ex, "CreateCharacterUsingDefaultCharacterValues failed");
                outputObject = new SuccessAndErrorMessage()
                {
                    Success = false,
                    ErrorMessage = "An internal error occurred. Please try again later."
                };

                return outputObject;
            }

            outputObject = new SuccessAndErrorMessage()
            {
                Success = true,
                ErrorMessage = ""
            };

            return outputObject;
        }

        //_PlayerGroupTypeID 0 returns all group types
        public async Task<IEnumerable<GetPlayerGroupsCharacterIsIn>> GetPlayerGroupsCharacterIsIn(Guid customerGUID, Guid userSessionGUID, string characterName, int playerGroupTypeID = 0)
        {
            IEnumerable<GetPlayerGroupsCharacterIsIn> outputObject;

            using (var conn = Connection)
            {
                var p = new DynamicParameters();
                p.Add("@CustomerGUID", customerGUID);
                p.Add("@CharName", characterName);
                p.Add("@UserSessionGUID", userSessionGUID);
                p.Add("@PlayerGroupTypeID", playerGroupTypeID);

                outputObject = await conn.QueryAsync<GetPlayerGroupsCharacterIsIn>("GetPlayerGroupsCharacterIsIn",
                    p,
                    commandType: CommandType.StoredProcedure);
            }

            return outputObject;
        }

        public async Task<User> GetUser(Guid customerGuid, Guid userGuid)
        {
            User outputObject = new User();

            using (var conn = Connection)
            {
                var p = new DynamicParameters();
                p.Add("@CustomerGUID", customerGuid);
                p.Add("@UserGUID", userGuid);

                outputObject = await conn.QuerySingleOrDefaultAsync<User>("GetUser",
                    p,
                    commandType: CommandType.StoredProcedure);
            }

            return outputObject;
        }

        public async Task<IEnumerable<User>> GetUsers(Guid customerGuid)
        {
            IEnumerable<User> outputObject = null;

            using (var conn = Connection)
            {
                var p = new DynamicParameters();
                p.Add("@CustomerGUID", customerGuid);

                try
                {
                    outputObject = await conn.QueryAsync<User>(GenericQueries.GetUsers, p);
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "GetUsers failed");
                }
            }

            return outputObject;
        }

        public async Task<GetUserSession> GetUserSession(Guid customerGUID, Guid userSessionGUID)
        {
            GetUserSession outputObject = new GetUserSession();

            using (var conn = Connection)
            {
                var p = new DynamicParameters();
                p.Add("@CustomerGUID", customerGUID);
                p.Add("@UserSessionGUID", userSessionGUID);

                outputObject = await conn.QuerySingleOrDefaultAsync<GetUserSession>("GetUserSession",
                    p,
                    commandType: CommandType.StoredProcedure);
            }

            return outputObject;
        }

        public async Task<GetUserSession> GetUserSessionORM(Guid customerGUID, Guid userSessionGUID)
        {
            GetUserSession outputObject = new GetUserSession();

            using (var conn = Connection)
            {
                outputObject = await conn.QueryFirstOrDefaultAsync<GetUserSession>(MSSQLQueries.GetUserSessionSQL, new { CustomerGUID = customerGUID, UserSessionGUID = userSessionGUID });
            }

            return outputObject;
        }

        public async Task<GetUserSessionComposite> GetUserSessionParallel(Guid customerGUID, Guid userSessionGUID) //id = UserSessionGUID
        {
            GetUserSessionComposite outputObject = new GetUserSessionComposite();
            UserSessions userSession = new UserSessions();
            User user = new User();
            Characters character = new Characters();

            using (var conn = Connection)
            {
                // First query must complete because subsequent queries depend on its results
                userSession = await conn.QueryFirstOrDefaultAsync<UserSessions>(MSSQLQueries.GetUserSessionOnlySQL, new { CustomerGUID = customerGUID, UserSessionGUID = userSessionGUID });

                if (userSession != null)
                {
                    // Run user and character queries in parallel on the same open connection
                    var userTask = conn.QueryFirstOrDefaultAsync<User>(MSSQLQueries.GetUserSQL, new { CustomerGUID = customerGUID, UserGUID = userSession.UserGuid });
                    var characterTask = conn.QueryFirstOrDefaultAsync<Characters>(MSSQLQueries.GetCharacterByNameSQL, new { CustomerGUID = customerGUID, CharacterName = userSession.SelectedCharacterName });

                    await Task.WhenAll(userTask, characterTask);

                    user = userTask.Result;
                    character = characterTask.Result;
                }
            }

            outputObject.userSession = userSession;
            outputObject.user = user;
            outputObject.character = character;

            return outputObject;
        }

        public async Task<PlayerLoginAndCreateSession> LoginAndCreateSession(Guid customerGUID, string email, string password, bool dontCheckPassword = false)
        {
            PlayerLoginAndCreateSession outputObject;

            using (var conn = Connection)
            {
                var p = new DynamicParameters();
                p.Add("@CustomerGUID", customerGUID);
                p.Add("@Email", email);
                p.Add("@Password", password);
                p.Add("@DontCheckPassword", dontCheckPassword);

                outputObject = await conn.QuerySingleOrDefaultAsync<PlayerLoginAndCreateSession>("PlayerLoginAndCreateSession",
                    p,
                    commandType: CommandType.StoredProcedure);
            }

            return outputObject;
        }

        public async Task<SuccessAndErrorMessage> Logout(Guid customerGuid, Guid userSessionGuid)
        {
            SuccessAndErrorMessage outputObject = new SuccessAndErrorMessage();

            try
            {
                using (var conn = Connection)
                {
                    var p = new DynamicParameters();
                    p.Add("@CustomerGUID", customerGuid);
                    p.Add("@UserSessionGUID", userSessionGuid);

                    await conn.ExecuteAsync(GenericQueries.Logout, p, commandType: CommandType.Text);
                }

                outputObject.Success = true;
                outputObject.ErrorMessage = "";

                return outputObject;
            }
            catch (Exception ex)
            {
                outputObject.Success = false;
                outputObject.ErrorMessage = "An internal error occurred. Please try again later.";
                Log.Error(ex, "Logout failed");

                return outputObject;
            }
        }

        public async Task<SuccessAndErrorMessage> UserSessionSetSelectedCharacter(Guid customerGUID, Guid userSessionGUID, string selectedCharacterName)
        {
            SuccessAndErrorMessage outputObject = new SuccessAndErrorMessage();

            try
            {
                using (var conn = Connection)
                {
                    var p = new DynamicParameters();
                    p.Add("@CustomerGUID", customerGUID);
                    p.Add("@UserSessionGUID", userSessionGUID);
                    p.Add("@SelectedCharacterName", selectedCharacterName);

                    await conn.ExecuteAsync("UserSessionSetSelectedCharacter",
                        p,
                        commandType: CommandType.StoredProcedure);
                }

                outputObject.Success = true;
                outputObject.ErrorMessage = "";

                return outputObject;
            }
            catch (Exception ex)
            {
                outputObject.Success = false;
                outputObject.ErrorMessage = "An internal error occurred. Please try again later.";
                Log.Error(ex, "UserSessionSetSelectedCharacter failed");

                return outputObject;
            }
        }

        public async Task<SuccessAndErrorMessage> RegisterUser(Guid customerGUID, string email, string password, string firstName, string lastName)
        {
            SuccessAndErrorMessage outputObject = new SuccessAndErrorMessage();

            try
            {
                using (var conn = Connection)
                {
                    var p = new DynamicParameters();
                    p.Add("@CustomerGUID", customerGUID);
                    p.Add("@Email", email);
                    p.Add("@Password", password);
                    p.Add("@FirstName", firstName);
                    p.Add("@LastName", lastName);
                    p.Add("@Role", "Player");
                    p.Add("@UserGUID", dbType: DbType.Guid, direction: ParameterDirection.Output);

                    await conn.ExecuteAsync("AddUser",
                        p,
                        commandType: CommandType.StoredProcedure);
                }

                outputObject.Success = true;
                outputObject.ErrorMessage = "";

                return outputObject;
            }
            catch (Exception ex)
            {
                outputObject.Success = false;
                outputObject.ErrorMessage = "An internal error occurred. Please try again later.";
                Log.Error(ex, "RegisterUser failed");

                return outputObject;
            }
        }

        public async Task<GetUserSession> GetUserFromEmail(Guid customerGUID, string email)
        {
            GetUserSession outputObject = new GetUserSession();

            using (var conn = Connection)
            {
                outputObject = await conn.QueryFirstOrDefaultAsync<GetUserSession>(MSSQLQueries.GetUserFromEmailSQL, new { CustomerGUID = customerGUID, Email = email });
            }

            return outputObject;
        }

        public async Task<SuccessAndErrorMessage> RemoveCharacter(Guid customerGUID, Guid userSessionGUID, string characterName)
        {
            SuccessAndErrorMessage outputObject = new SuccessAndErrorMessage();

            try
            {
                using (var conn = Connection)
                {
                    var p = new DynamicParameters();
                    p.Add("@CustomerGUID", customerGUID);
                    p.Add("@UserSessionGUID", userSessionGUID);
                    p.Add("@CharacterName", characterName);

                    await conn.ExecuteAsync("RemoveCharacter",
                        p,
                        commandType: CommandType.StoredProcedure);
                }

                outputObject.Success = true;
                outputObject.ErrorMessage = "";

                return outputObject;
            }
            catch (Exception ex)
            {
                outputObject.Success = false;
                outputObject.ErrorMessage = "An internal error occurred. Please try again later.";
                Log.Error(ex, "RemoveCharacter failed");

                return outputObject;
            }
        }

        public async Task<SuccessAndErrorMessage> UpdateUser(Guid customerGuid, Guid userGuid, string firstName, string lastName, string email)
        {
            SuccessAndErrorMessage outputObject = new SuccessAndErrorMessage();

            try
            {
                using (var conn = Connection)
                {
                    var p = new DynamicParameters();
                    p.Add("@CustomerGUID", customerGuid);
                    p.Add("@UserGUID", userGuid);
                    p.Add("@FirstName", firstName);
                    p.Add("@LastName", lastName);
                    p.Add("@Email", email);

                    await conn.ExecuteAsync(GenericQueries.UpdateUser,
                        p,
                        commandType: CommandType.Text);
                }

                outputObject.Success = true;
                outputObject.ErrorMessage = "";

                return outputObject;
            }
            catch (Exception ex)
            {
                outputObject.Success = false;
                outputObject.ErrorMessage = "An internal error occurred. Please try again later.";
                Log.Error(ex, "UpdateUser failed");

                return outputObject;
            }
        }
    }
}
