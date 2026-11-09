using Stellaegis.Primitives;

namespace Stellaegis.Identity.Tests;

/// <summary>
/// The approvals of a hand delivery as a host's rights system would keep them: a request, approved by a second person
/// through <see cref="Approve"/>, spent once by the account and the caller it was asked for.
/// </summary>
internal sealed class TestHandDeliveryApprovals : IHandDeliveryApprovals
{
    private readonly Lock _lock = new();
    private readonly Dictionary<Guid, Request> _requests = [];

    public Task<Guid> RequestAsync(Subject subject, Actor requestedBy, CancellationToken cancellationToken = default)
    {
        var id = Guid.NewGuid();
        lock (_lock)
            _requests[id] = new Request(subject, requestedBy);
        return Task.FromResult(id);
    }

    /// <summary>A person grants the request — never its requester, whom the rights system would refuse.</summary>
    public void Approve(Guid approval, Actor by)
    {
        lock (_lock)
        {
            var request = _requests[approval];
            Assert.NotEqual(request.RequestedBy.Value, by.Value);
            request.ApprovedBy = by;
        }
    }

    public Task<bool> TryConsumeAsync(Guid approval, Subject subject, Actor requestedBy, CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            if (!_requests.TryGetValue(approval, out var request) || request.Spent || request.ApprovedBy is null
                || request.Subject != subject || request.RequestedBy.Value != requestedBy.Value)
                return Task.FromResult(false);
            request.Spent = true;
            return Task.FromResult(true);
        }
    }

    private sealed class Request(Subject subject, Actor requestedBy)
    {
        public Subject Subject { get; } = subject;
        public Actor RequestedBy { get; } = requestedBy;
        public Actor? ApprovedBy { get; set; }
        public bool Spent { get; set; }
    }
}
