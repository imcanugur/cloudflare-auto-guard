/**
 * Request count threshold evaluation policy
 */

export class ThresholdPolicy {
  /**
   * Returns true if request volume equals or exceeds the defined threshold
   */
  public static isThresholdExceeded(requestCount: number, threshold: number): boolean {
    return requestCount >= threshold;
  }
}
