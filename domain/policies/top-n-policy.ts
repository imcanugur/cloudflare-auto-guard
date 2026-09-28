/**
 * Top-N candidate ranking policy
 */

export class TopNPolicy {
  /**
   * Determines if a candidate's rank falls within the allowable Top-N cutoff.
   * Rank 1 is the highest traffic contributor.
   */
  public static isWithinTopN(rank: number, topN: number): boolean {
    if (rank <= 0) return false;
    return rank <= topN;
  }
}
