using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Puniemu.Anticheat;

public sealed class AnticheatState
{
    [JsonPropertyName("previous_balances")]
    public Dictionary<string, long> PreviousBalances { get; set; } = new();
    [JsonPropertyName("claimed_deltas")]
    public Dictionary<string, long> ClaimedDeltas { get; set; } = new();
    [JsonPropertyName("stage_state")]
    public string? StageState { get; set; }
    [JsonPropertyName("owned_items")]
    public List<string> OwnedItems { get; set; } = new();
    [JsonPropertyName("owned_yokai")]
    public List<string> OwnedYokai { get; set; } = new();
    [JsonPropertyName("reward_cause")]
    public string? RewardCause { get; set; }
    [JsonPropertyName("session_known_sequence")]
    public ulong? SessionKnownSequence { get; set; }
    [JsonPropertyName("account_risk_score")]
    public byte AccountRiskScore { get; set; }
}

public sealed class AnticheatVerdict
{
    public bool Allowed { get; set; }
    public string Action { get; set; } = "Deny";
    public byte RiskScore { get; set; }
    public JsonElement Findings { get; set; }
    public string AuditId { get; set; } = string.Empty;
    public bool IsAllowed() => Allowed;
}

public sealed class AnticheatAdapter : IDisposable
{
    private readonly HttpClient _http;
    private readonly string _baseUrl;
    private readonly string _token;
    private readonly bool _failClosed;
    private readonly string _mode;

    public AnticheatAdapter(string baseUrl, string token, bool failClosed = true, string mode = "enforce")
    {
        _baseUrl = baseUrl.TrimEnd('/');
        _token = token;
        _failClosed = failClosed;
        _mode = mode;
        _http = new HttpClient { Timeout = TimeSpan.FromMilliseconds(250) };
    }

    public async Task<AnticheatVerdict> CheckAsync(
        string accountId,
        string sessionId,
        string requestId,
        ulong sequence,
        string endpoint,
        JsonElement payload,
        AnticheatState? state,
        string? ip = null,
        string? device = null,
        string? udkey = null,
        string? gdkey = null,
        bool isAdmin = false,
        CancellationToken cancellationToken = default)
    {
        if (_mode == "off")
        {
            return new AnticheatVerdict { Allowed = true, Action = "Allow" };
        }
        var envelope = new
        {
            account_id = accountId,
            session_id = sessionId,
            request_id = requestId,
            sequence,
            nonce = Guid.NewGuid().ToString("N"),
            timestamp_ms = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            endpoint,
            ip,
            device_fingerprint = device,
            udkey,
            gdkey,
            is_admin = isAdmin,
            payload,
            state = state ?? new AnticheatState()
        };
        var body = JsonSerializer.Serialize(envelope);
        var bytes = Encoding.UTF8.GetBytes(body);
        if (bytes.Length > 262144)
        {
            return new AnticheatVerdict { Allowed = false, Action = "Deny" };
        }
        var signature = Sign(bytes);
        using var request = new HttpRequestMessage(HttpMethod.Post, _baseUrl + "/check");
        request.Content = new ByteArrayContent(bytes);
        request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
        request.Headers.Add("X-Anticheat-Token", signature);
        request.Headers.Add("X-Request-Id", requestId);
        try
        {
            using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            var verdict = await response.Content.ReadFromJsonAsync<AnticheatVerdict>(cancellationToken: cancellationToken).ConfigureAwait(false);
            if (verdict == null)
            {
                return new AnticheatVerdict { Allowed = !_failClosed, Action = _failClosed ? "Deny" : "AllowAndLog" };
            }
            if (_mode == "shadow" || _mode == "log_only")
            {
                verdict.Allowed = true;
            }
            return verdict;
        }
        catch
        {
            return new AnticheatVerdict { Allowed = !_failClosed, Action = _failClosed ? "Deny" : "AllowAndLog" };
        }
    }

    private string Sign(byte[] body)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(_token));
        var hash = hmac.ComputeHash(body);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public void Dispose()
    {
        _http.Dispose();
    }
}
