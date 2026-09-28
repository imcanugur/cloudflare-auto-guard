/**
 * Exponential backoff retry utility with jitter
 */

export interface RetryOptions {
  maxRetries?: number;
  initialDelayMs?: number;
  maxDelayMs?: number;
  backoffFactor?: number;
  shouldRetry?: (error: unknown, attempt: number) => boolean;
}

const DEFAULT_OPTIONS: Required<RetryOptions> = {
  maxRetries: 3,
  initialDelayMs: 1000,
  maxDelayMs: 8000,
  backoffFactor: 2,
  shouldRetry: (error: unknown) => {
    if (error && typeof error === "object" && "statusCode" in error) {
      const status = (error as { statusCode: number }).statusCode;
      return status === 429 || (status >= 500 && status <= 504);
    }
    return true;
  }
};

export async function withRetry<T>(
  fn: () => Promise<T>,
  options?: RetryOptions
): Promise<T> {
  const opts: Required<RetryOptions> = { ...DEFAULT_OPTIONS, ...options };
  let attempt = 0;

  while (true) {
    try {
      return await fn();
    } catch (error) {
      attempt++;
      if (attempt > opts.maxRetries || !opts.shouldRetry(error, attempt)) {
        throw error;
      }

      // Calculate exponential backoff with full jitter
      const calculatedDelay = Math.min(
        opts.maxDelayMs,
        opts.initialDelayMs * Math.pow(opts.backoffFactor, attempt - 1)
      );
      const delay = Math.floor(Math.random() * calculatedDelay);

      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
}
