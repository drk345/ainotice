/**
 * Dictionary Data Index
 *
 * Static imports of JSON dictionary data.
 * This enables deterministic loading without dynamic FS access.
 *
 * @see AG-PROMPT-062: Datafy dictionaries
 */

import financeData from './finance.json';
import hrData from './hr.json';
import legalData from './legal.json';

export { financeData, hrData, legalData };

/** All dictionary data files */
export const ALL_DICTIONARY_DATA = [financeData, hrData, legalData] as const;
