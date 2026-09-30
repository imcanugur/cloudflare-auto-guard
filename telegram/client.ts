/**
 * Telegram Bot API HTTP Client for Cloudflare Workers
 */
import { SendMessageOptions } from "@/telegram/types";
import { logger } from "@/observability/logger";

export class TelegramClient {
  private botToken: string;
  private baseUrl: string;

  constructor(botToken: string) {
    this.botToken = botToken;
    this.baseUrl = `https://api.telegram.org/bot${botToken}`;
  }

  public isConfigured(): boolean {
    return Boolean(this.botToken && this.botToken.length > 10);
  }

  /**
   * Sends a message to a Telegram chat
   */
  public async sendMessage(
    chatId: number | string,
    text: string,
    options: SendMessageOptions = {}
  ): Promise<boolean> {
    if (!this.isConfigured()) return false;

    try {
      const response = await fetch(`${this.baseUrl}/sendMessage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: chatId,
          text,
          parse_mode: options.parse_mode ?? "HTML",
          reply_markup: options.reply_markup,
          disable_web_page_preview: options.disable_web_page_preview ?? true
        })
      });

      if (!response.ok) {
        const errBody = await response.text();
        logger.warn("TELEGRAM_SEND_MESSAGE_FAILED", {
          status: response.status,
          response: errBody
        });
        return false;
      }

      return true;
    } catch (err) {
      logger.error("TELEGRAM_NETWORK_ERROR", {
        message: (err as Error).message
      });
      return false;
    }
  }

  /**
   * Updates an existing message's text and inline buttons
   */
  public async editMessageText(
    chatId: number | string,
    messageId: number,
    text: string,
    options: SendMessageOptions = {}
  ): Promise<boolean> {
    if (!this.isConfigured()) return false;

    try {
      const response = await fetch(`${this.baseUrl}/editMessageText`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: chatId,
          message_id: messageId,
          text,
          parse_mode: options.parse_mode ?? "HTML",
          reply_markup: options.reply_markup,
          disable_web_page_preview: options.disable_web_page_preview ?? true
        })
      });

      return response.ok;
    } catch {
      return false;
    }
  }

  /**
   * Answers a callback query from an inline keyboard button
   */
  public async answerCallbackQuery(
    callbackQueryId: string,
    text?: string,
    showAlert = false
  ): Promise<boolean> {
    if (!this.isConfigured()) return false;

    try {
      const response = await fetch(`${this.baseUrl}/answerCallbackQuery`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          callback_query_id: callbackQueryId,
          text,
          show_alert: showAlert
        })
      });

      return response.ok;
    } catch {
      return false;
    }
  }

  /**
   * Registers the worker URL as the Telegram webhook endpoint
   */
  public async setWebhook(url: string, secretToken?: string): Promise<{ ok: boolean; description?: string }> {
    if (!this.isConfigured()) {
      return { ok: false, description: "TELEGRAM_BOT_TOKEN is missing or invalid." };
    }

    try {
      const payload: Record<string, unknown> = {
        url,
        allowed_updates: ["message", "callback_query"]
      };
      if (secretToken) {
        payload.secret_token = secretToken;
      }

      const response = await fetch(`${this.baseUrl}/setWebhook`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });

      return (await response.json()) as { ok: boolean; description?: string };
    } catch (err) {
      return { ok: false, description: (err as Error).message };
    }
  }
}
