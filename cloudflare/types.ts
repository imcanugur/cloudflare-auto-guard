/**
 * Cloudflare Lists API types and request/response contracts
 */

export interface CloudflareListItem {
  id: string;
  ip: string;
  comment?: string;
  created_on?: string;
  modified_on?: string;
}

export interface CloudflareCreateListItemPayload {
  ip: string;
  comment?: string;
}

export interface CloudflareApiResponse<T> {
  result: T;
  success: boolean;
  errors: Array<{ code: number; message: string }>;
  messages: Array<{ code: number; message: string }>;
  result_info?: {
    page: number;
    per_page: number;
    count: number;
    total_count: number;
  };
}

export interface CloudflareListOperationResult {
  operation_id: string;
  status: string;
}
