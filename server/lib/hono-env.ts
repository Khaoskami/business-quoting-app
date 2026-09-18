import type { Tier } from './tier';
import { TIER_LIMITS } from './tier';

export type AppVariables = {
  userId:     string;
  userEmail:  string;
  isAdmin:    boolean;
  tier:       Tier;
  tierLimits: typeof TIER_LIMITS[Tier];
};

export type AppEnv = { Variables: AppVariables };
