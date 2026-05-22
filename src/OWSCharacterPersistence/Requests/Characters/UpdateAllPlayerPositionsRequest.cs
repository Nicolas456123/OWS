using OWSData.Models.Composites;
using OWSData.Repositories.Interfaces;
using OWSShared.Interfaces;
using Serilog;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;

namespace OWSCharacterPersistence.Requests.Characters
{
    public class UpdateAllPlayerPositionsRequest
    {
        public string SerializedPlayerLocationData { get; set; }
        public string MapName { get; set; }

        private Guid customerGUID;
        private ICharactersRepository charactersRepository;

        // World axis bound. UE5's UE_OLD_WORLD_MAX was 2,097,152 cm; large-world support
        // raised it to ~21M km, but for OWS persistence anything beyond a few thousand km
        // is clearly out-of-bounds. 1e9 cm (~10,000 km) is a generous ceiling that still
        // rejects float.MaxValue, NaN, Inf and obvious griefing/garbage payloads.
        private const float MaxCoordinate = 1e9f;

        public void SetData(ICharactersRepository charactersRepository, IHeaderCustomerGUID customerGuid)
        {
            this.charactersRepository = charactersRepository;
            customerGUID = customerGuid.CustomerGUID;
        }

        public async Task<SuccessAndErrorMessage> Handle()
        {
            SuccessAndErrorMessage successAndErrorMessage = new SuccessAndErrorMessage();

            if (string.IsNullOrEmpty(SerializedPlayerLocationData))
            {
                successAndErrorMessage.Success = true;
                return successAndErrorMessage;
            }

            int rejected = 0;
            foreach (string PlayerDataString in SerializedPlayerLocationData.Split('|'))
            {
                if (string.IsNullOrEmpty(PlayerDataString)) { continue; }

                string[] PlayerDataValues = PlayerDataString.Split(':');

                // Expected layout: name:X:Y:Z:RX:RY:RZ — anything shorter is malformed.
                if (PlayerDataValues.Length < 7)
                {
                    rejected++;
                    continue;
                }

                string PlayerName = PlayerDataValues[0];

                // TryParse with InvariantCulture so a comma-decimal client locale can't
                // change parsing semantics on the server.
                if (!float.TryParse(PlayerDataValues[1], NumberStyles.Float, CultureInfo.InvariantCulture, out float X) ||
                    !float.TryParse(PlayerDataValues[2], NumberStyles.Float, CultureInfo.InvariantCulture, out float Y) ||
                    !float.TryParse(PlayerDataValues[3], NumberStyles.Float, CultureInfo.InvariantCulture, out float Z) ||
                    !float.TryParse(PlayerDataValues[4], NumberStyles.Float, CultureInfo.InvariantCulture, out float RX) ||
                    !float.TryParse(PlayerDataValues[5], NumberStyles.Float, CultureInfo.InvariantCulture, out float RY) ||
                    !float.TryParse(PlayerDataValues[6], NumberStyles.Float, CultureInfo.InvariantCulture, out float RZ))
                {
                    rejected++;
                    continue;
                }

                // Reject NaN / Inf / huge coordinates. NaN especially must never reach the DB —
                // PostgreSQL real columns accept it, but every later sort/comparison breaks.
                if (!IsValidCoord(X) || !IsValidCoord(Y) || !IsValidCoord(Z) ||
                    !IsValidCoord(RX) || !IsValidCoord(RY) || !IsValidCoord(RZ))
                {
                    rejected++;
                    continue;
                }

                await charactersRepository.UpdatePosition(customerGUID, PlayerName, MapName, X, Y, Z, RX, RY, RZ);
            }

            if (rejected > 0)
            {
                Log.Warning("UpdateAllPlayerPositions: rejected {Count} malformed/out-of-range entries (map={MapName})",
                    rejected, MapName);
            }

            successAndErrorMessage.Success = true;
            return successAndErrorMessage;
        }

        private static bool IsValidCoord(float v) =>
            float.IsFinite(v) && Math.Abs(v) <= MaxCoordinate;
    }
}
