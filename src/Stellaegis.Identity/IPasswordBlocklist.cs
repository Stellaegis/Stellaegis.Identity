namespace Stellaegis.Identity;

/// <summary>
/// The passwords refused whatever their shape: the ones everyone chooses, the ones already in the breaches. NIST
/// SP 800-63B asks for the check and lets the composition rules go; the module asks the question wherever a password
/// is accepted — a registration, an activation, a reset, a change — and ships no answer: a host registers one, as a
/// singleton, on a list of its own or a service it accepts to call. Without one, no password is refused for this.
/// </summary>
public interface IPasswordBlocklist
{
    /// <summary>Whether <paramref name="password"/> is refused.</summary>
    ValueTask<bool> IsBlockedAsync(string password, CancellationToken cancellationToken = default);
}
