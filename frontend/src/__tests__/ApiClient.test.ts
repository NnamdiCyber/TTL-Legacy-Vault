import { ApiClient, ApiError } from "../api/client";

function mockResponse(
  body: unknown,
  init: { status?: number; headers?: Record<string, string> } = {},
): Response {
  const status = init.status ?? 200;
  const headerMap = new Map<string, string>(
    Object.entries(init.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]),
  );

  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get: (name: string) => headerMap.get(name.toLowerCase()) ?? null,
    } as Headers,
    text: async () => (body === undefined ? "" : JSON.stringify(body)),
  } as Response;
}

describe("ApiClient", () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    document.cookie = "__Host-csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
  });

  afterEach(() => {
    global.fetch = originalFetch;
    jest.restoreAllMocks();
  });

  it("URL-encodes vaultId in reminder preferences endpoints", async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValueOnce(mockResponse({ vault_id: "a/b?c#d" }))
      .mockResolvedValueOnce(mockResponse({ csrf_token: "tok-1" }))
      .mockResolvedValueOnce(mockResponse({ vault_id: "a/b?c#d" }));
    global.fetch = fetchMock;

    const client = new ApiClient({ baseUrl: "https://api.example.com" });
    await client.getReminderPreferences("a/b?c#d");
    await client.setReminderPreferences("a/b?c#d", {
      channels: ["email"],
      hours_before_expiry: 24,
      frequency: "daily",
    });

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "https://api.example.com/api/vaults/a%2Fb%3Fc%23d/reminder-preferences",
      expect.objectContaining({ method: "GET" }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      3,
      "https://api.example.com/api/vaults/a%2Fb%3Fc%23d/reminder-preferences",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("caches CSRF token and updates it from rotated x-csrf-token response header", async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValueOnce(mockResponse({ csrf_token: "initial-csrf" }))
      .mockResolvedValueOnce(
        mockResponse({ id: 1 }, { headers: { "x-csrf-token": "rotated-csrf" } }),
      )
      .mockResolvedValueOnce(mockResponse({ id: 1 }));
    global.fetch = fetchMock;

    const client = new ApiClient({ baseUrl: "https://api.example.com" });
    await client.approveUpgradeProposal(1);
    await client.rejectUpgradeProposal(1);

    // Only one /api/csrf-token call should have been made
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock.mock.calls[0][0]).toBe("https://api.example.com/api/csrf-token");

    const firstMutatingHeaders = fetchMock.mock.calls[1][1]?.headers as Headers;
    expect(firstMutatingHeaders.get("x-csrf-token")).toBe("initial-csrf");

    const secondMutatingHeaders = fetchMock.mock.calls[2][1]?.headers as Headers;
    expect(secondMutatingHeaders.get("x-csrf-token")).toBe("rotated-csrf");
  });

  it("reads CSRF cookie separated without whitespace and handles malformed percent-encoding", async () => {
    jest.spyOn(document, "cookie", "get").mockReturnValue("foo=bar;__Host-csrf=raw%E0%A4%Avalue");

    const fetchMock = jest.fn().mockResolvedValueOnce(mockResponse({ id: 2 }));
    global.fetch = fetchMock;

    const client = new ApiClient({ baseUrl: "https://api.example.com" });
    await client.approveUpgradeProposal(2);

    const headers = fetchMock.mock.calls[0][1]?.headers as Headers;
    expect(headers.get("x-csrf-token")).toBe("raw%E0%A4%Avalue");
  });

  it("extracts error message from { error } and { code, message } responses", async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValueOnce(mockResponse({ error: "vault_not_found" }, { status: 404 }))
      .mockResolvedValueOnce(
        mockResponse({ code: "csrf_invalid", message: "CSRF token missing" }, { status: 403 }),
      );
    global.fetch = fetchMock;

    const client = new ApiClient({ baseUrl: "https://api.example.com" });

    await expect(client.getHealth()).rejects.toThrow(new ApiError("vault_not_found", 404));
    await expect(client.getReady()).rejects.toThrow(new ApiError("CSRF token missing", 403));
  });
});
