import { describe, it, expect, vi } from "vitest";
import { Blocker } from "@/guard/blocker";
import { GuardDecision } from "@/domain/models/decision";
import { ITrafficRepository } from "@/storage/traffic-repository";
import { CloudflareListsService } from "@/cloudflare/lists";

describe("Blocker — Dry Run, Real Mutation & Failure Isolation", () => {
  const dummyDecision: GuardDecision = {
    action: "BLOCK",
    reason: "POLICY_MATCH",
    ip: "203.0.113.10",
    country: "US",
    requestCount: 2500,
    rank: 1,
    threshold: 2000,
    windowSeconds: 300
  };

  it("handles dry-run mode without invoking Cloudflare API", async () => {
    const mockRepo: ITrafficRepository = {
      record: vi.fn(),
      getAllShardsTopN: vi.fn(),
      isBlocked: vi.fn().mockResolvedValue(false),
      markBlocked: vi.fn()
    };

    const mockListsService = {
      addIpToList: vi.fn()
    } as unknown as CloudflareListsService;

    const blocker = new Blocker(mockRepo, mockListsService, {
      listId: "test-list-id",
      dryRun: true
    });

    const result = await blocker.executeBlock(dummyDecision);

    expect(result.action).toBe("BLOCK");
    expect(mockListsService.addIpToList).not.toHaveBeenCalled();
    expect(mockRepo.markBlocked).not.toHaveBeenCalled();
  });

  it("executes real block and marks IP blocked in storage", async () => {
    const mockRepo: ITrafficRepository = {
      record: vi.fn(),
      getAllShardsTopN: vi.fn(),
      isBlocked: vi.fn().mockResolvedValue(false),
      markBlocked: vi.fn()
    };

    const mockListsService = {
      addIpToList: vi.fn().mockResolvedValue({ operation_id: "op-123", status: "completed" })
    } as unknown as CloudflareListsService;

    const blocker = new Blocker(mockRepo, mockListsService, {
      listId: "test-list-id",
      dryRun: false
    });

    const result = await blocker.executeBlock(dummyDecision);

    expect(result.action).toBe("BLOCK");
    expect(mockListsService.addIpToList).toHaveBeenCalledWith(
      "test-list-id",
      "203.0.113.10",
      expect.stringContaining("Auto Guard: US")
    );
    expect(mockRepo.markBlocked).toHaveBeenCalledWith("203.0.113.10");
  });

  it("isolates Cloudflare API failure and returns BLOCK_FAILED without throwing", async () => {
    const mockRepo: ITrafficRepository = {
      record: vi.fn(),
      getAllShardsTopN: vi.fn(),
      isBlocked: vi.fn().mockResolvedValue(false),
      markBlocked: vi.fn()
    };

    const mockListsService = {
      addIpToList: vi.fn().mockRejectedValue(new Error("Cloudflare 500 Internal Error"))
    } as unknown as CloudflareListsService;

    const blocker = new Blocker(mockRepo, mockListsService, {
      listId: "test-list-id",
      dryRun: false
    });

    const result = await blocker.executeBlock(dummyDecision);

    expect(result.reason).toBe("BLOCK_FAILED");
    expect(mockRepo.markBlocked).not.toHaveBeenCalled();
  });
});
