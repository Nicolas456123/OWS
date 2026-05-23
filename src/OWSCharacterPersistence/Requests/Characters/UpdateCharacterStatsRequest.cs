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
        // Bounds. The stats DTO carries 80+ floats — without validation, a cheating client
        // can push Health=float.MaxValue (corrupts UI math, lets overflows bleed through any
        // server-side arithmetic) or Position=NaN (corrupts cached world state). We clamp
        // rather than reject so a desynced client doesn't lose its save outright — but the
        // cap is wide enough that any legitimate buff stays untouched.
        //
        // Position bound mirrors UpdateAllPlayerPositionsRequest (commit d0f9bba): 10 000 km
        // covers any realistic MMO world. Rotation in degrees gets ±360° (more is just
        // wraparound). Generic stats get a billion — wide enough for any buff stack, narrow
        // enough that integer overflows downstream stay impossible.
        private const float MaxPositionAbs = 10_000_000f;   // 10 000 km in centimeters
        private const float MaxRotationAbs = 360f;
        private const float MaxStatValue = 1_000_000_000f;  // 1 billion
        private const int MaxLevel = 1000;
        private const int MaxCurrency = int.MaxValue / 2;   // ~1.07 billion, leaves headroom for sums
        private const int MaxDescriptionLength = 4096;

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

            if (updateCharacterStats == null)
            {
                Log.Warning("UpdateCharacterStats rejected: null payload (Customer={Customer})", customerGUID);
                successAndErrorMessage.Success = false;
                successAndErrorMessage.ErrorMessage = "Invalid character stats.";
                return successAndErrorMessage;
            }

            // Defense in depth: clamp every numeric input. NaN/Inf are replaced with 0 (the
            // stored proc would otherwise propagate Inf into MAX(...) aggregates and corrupt
            // leaderboards). Cap each kind of field at its plausible upper bound.
            SanitizeStats(updateCharacterStats);

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

        // -------------------------------------------------------------------------
        // Clamping helpers — kept in this file (single call site) rather than in a
        // shared validator: only this handler binds the full UpdateCharacterStats
        // surface and the rules are policy-tied to it (position bound mirrors the
        // movement RPC's bound, etc.).
        // -------------------------------------------------------------------------

        private static float ClampStat(float v) =>
            !float.IsFinite(v) ? 0f : Math.Clamp(v, 0f, MaxStatValue);

        private static float ClampSignedStat(float v) =>
            !float.IsFinite(v) ? 0f : Math.Clamp(v, -MaxStatValue, MaxStatValue);

        private static float ClampPosition(float v) =>
            !float.IsFinite(v) ? 0f : Math.Clamp(v, -MaxPositionAbs, MaxPositionAbs);

        private static float ClampRotation(float v) =>
            !float.IsFinite(v) ? 0f : Math.Clamp(v, -MaxRotationAbs, MaxRotationAbs);

        private static int ClampCurrency(int v) => Math.Clamp(v, 0, MaxCurrency);

        private void SanitizeStats(UpdateCharacterStats s)
        {
            // Identity + cosmetic
            s.CharacterLevel = Math.Clamp(s.CharacterLevel, 1, MaxLevel);
            s.Gender = Math.Clamp(s.Gender, 0, 64);
            s.Size = Math.Clamp(s.Size, 0, 1000);
            s.Weight = ClampStat(s.Weight);
            s.Fame = ClampSignedStat(s.Fame);              // can be negative (notoriety)
            s.Alignment = ClampSignedStat(s.Alignment);    // typically -100..+100 but allow more
            s.XP = Math.Max(0, s.XP);
            if (s.Description != null && s.Description.Length > MaxDescriptionLength)
                s.Description = s.Description.Substring(0, MaxDescriptionLength);

            // World transform — mirrors UpdateAllPlayerPositions clamping policy
            s.X = ClampPosition(s.X);
            s.Y = ClampPosition(s.Y);
            s.Z = ClampPosition(s.Z);
            s.RX = ClampRotation(s.RX);
            s.RY = ClampRotation(s.RY);
            s.RZ = ClampRotation(s.RZ);

            s.TeamNumber = Math.Max(0, s.TeamNumber);
            s.HitDie = Math.Max(0, s.HitDie);

            // Resource pools — sanitize the Max first, then clamp current against the (now safe) Max
            s.MaxHealth = ClampStat(s.MaxHealth); s.Health = Math.Clamp(ClampStat(s.Health), 0f, Math.Max(s.MaxHealth, 0f));
            s.MaxMana = ClampStat(s.MaxMana); s.Mana = Math.Clamp(ClampStat(s.Mana), 0f, Math.Max(s.MaxMana, 0f));
            s.MaxEnergy = ClampStat(s.MaxEnergy); s.Energy = Math.Clamp(ClampStat(s.Energy), 0f, Math.Max(s.MaxEnergy, 0f));
            s.MaxFatigue = ClampStat(s.MaxFatigue); s.Fatigue = Math.Clamp(ClampStat(s.Fatigue), 0f, Math.Max(s.MaxFatigue, 0f));
            s.MaxStamina = ClampStat(s.MaxStamina); s.Stamina = Math.Clamp(ClampStat(s.Stamina), 0f, Math.Max(s.MaxStamina, 0f));
            s.MaxEndurance = ClampStat(s.MaxEndurance); s.Endurance = Math.Clamp(ClampStat(s.Endurance), 0f, Math.Max(s.MaxEndurance, 0f));

            s.HealthRegenRate = ClampSignedStat(s.HealthRegenRate);   // negative = bleed
            s.ManaRegenRate = ClampSignedStat(s.ManaRegenRate);
            s.EnergyRegenRate = ClampSignedStat(s.EnergyRegenRate);
            s.FatigueRegenRate = ClampSignedStat(s.FatigueRegenRate);
            s.StaminaRegenRate = ClampSignedStat(s.StaminaRegenRate);
            s.EnduranceRegenRate = ClampSignedStat(s.EnduranceRegenRate);
            s.Wounds = ClampStat(s.Wounds);
            s.Thirst = ClampStat(s.Thirst);
            s.Hunger = ClampStat(s.Hunger);

            // Primary attributes
            s.Strength = ClampStat(s.Strength);
            s.Dexterity = ClampStat(s.Dexterity);
            s.Constitution = ClampStat(s.Constitution);
            s.Intellect = ClampStat(s.Intellect);
            s.Wisdom = ClampStat(s.Wisdom);
            s.Charisma = ClampStat(s.Charisma);
            s.Agility = ClampStat(s.Agility);
            s.Spirit = ClampStat(s.Spirit);
            s.Magic = ClampStat(s.Magic);
            s.Fortitude = ClampStat(s.Fortitude);
            s.Reflex = ClampStat(s.Reflex);
            s.Willpower = ClampStat(s.Willpower);

            // Combat — many can stack negative (debuffs) so use signed bound
            s.BaseAttack = ClampSignedStat(s.BaseAttack);
            s.BaseAttackBonus = ClampSignedStat(s.BaseAttackBonus);
            s.AttackPower = ClampSignedStat(s.AttackPower);
            s.AttackSpeed = ClampStat(s.AttackSpeed);
            s.CritChance = ClampStat(s.CritChance);
            s.CritMultiplier = ClampStat(s.CritMultiplier);
            s.Haste = ClampSignedStat(s.Haste);
            s.SpellPower = ClampSignedStat(s.SpellPower);
            s.SpellPenetration = ClampStat(s.SpellPenetration);
            s.Defense = ClampStat(s.Defense);
            s.Dodge = ClampStat(s.Dodge);
            s.Parry = ClampStat(s.Parry);
            s.Avoidance = ClampStat(s.Avoidance);
            s.Versatility = ClampStat(s.Versatility);
            s.Multishot = ClampStat(s.Multishot);
            s.Initiative = ClampSignedStat(s.Initiative);
            s.NaturalArmor = ClampStat(s.NaturalArmor);
            s.PhysicalArmor = ClampStat(s.PhysicalArmor);
            s.BonusArmor = ClampSignedStat(s.BonusArmor);
            s.ForceArmor = ClampStat(s.ForceArmor);
            s.MagicArmor = ClampStat(s.MagicArmor);
            s.Resistance = ClampSignedStat(s.Resistance);
            s.ReloadSpeed = ClampStat(s.ReloadSpeed);
            s.Range = ClampStat(s.Range);
            s.Speed = ClampStat(s.Speed);

            // Currencies — never negative, capped to half int.MaxValue so sums don't overflow
            s.Gold = ClampCurrency(s.Gold);
            s.Silver = ClampCurrency(s.Silver);
            s.Copper = ClampCurrency(s.Copper);
            s.FreeCurrency = ClampCurrency(s.FreeCurrency);
            s.PremiumCurrency = ClampCurrency(s.PremiumCurrency);

            // Skills
            s.Perception = ClampStat(s.Perception);
            s.Acrobatics = ClampStat(s.Acrobatics);
            s.Climb = ClampStat(s.Climb);
            s.Stealth = ClampStat(s.Stealth);
            s.Score = Math.Max(0, s.Score);
        }
    }
}
