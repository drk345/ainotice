/**
 * Locale Profile Data Index
 *
 * Static imports of JSON locale profile data.
 * This enables deterministic loading without dynamic FS access.
 *
 * @see AG-PROMPT-063: Datafy locale profiles
 */

import euNordicsData from './eu-nordics.json';
import usData from './us.json';
import ukData from './uk.json';
import euDachData from './eu-dach.json';
import euWesternData from './eu-western.json';
import euSouthernData from './eu-southern.json';
import euEasternData from './eu-eastern.json';
import enCommonwealthData from './en-commonwealth.json';
import latamData from './latam.json';
import unknownData from './unknown.json';

export {
  euNordicsData,
  usData,
  ukData,
  euDachData,
  euWesternData,
  euSouthernData,
  euEasternData,
  enCommonwealthData,
  latamData,
  unknownData,
};

/** All locale profile data files */
export const ALL_LOCALE_PROFILE_DATA = [
  euNordicsData,
  usData,
  ukData,
  euDachData,
  euWesternData,
  euSouthernData,
  euEasternData,
  enCommonwealthData,
  latamData,
  unknownData,
] as const;
