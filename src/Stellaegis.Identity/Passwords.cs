using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>
/// Hashes passwords with PBKDF2-SHA256, a random salt and the pepper of the host, in a self-describing form,
/// <c>pbkdf2_sha256$iterations$salt_b64$hash_b64</c>: a hash carries its own iteration count, so the count can
/// be raised without touching the stored hashes.
/// </summary>
public sealed class PasswordHasher
{
    // A hash to verify against when the account does not exist, so that the attempt costs the same time.
    // Not a secret: its only purpose is the work it takes.
    private const string DummyStoredHash =
        "pbkdf2_sha256$310000$2g9y9xq2xW2mRjKf8fQZ0Q==$uG2H8m8l7TtG5eZV4fM8l2oR7x8p1gQmQG8p3Qb8v1k=";

    private readonly string _pepper;
    private readonly int _iterations;

    /// <summary>Creates the hasher from the options of the module, whose pepper is required.</summary>
    public PasswordHasher(IOptions<IdentityOptions> options)
    {
        var hasher = Guard.NotNull(options).Value.PasswordHasher;
        _pepper = Guard.NotWhiteSpace(hasher.Pepper);
        _iterations = hasher.Iterations;
    }

    /// <summary>Hashes <paramref name="password"/> with a fresh 16-byte salt.</summary>
    /// <exception cref="ArgumentException"><paramref name="password"/> is blank.</exception>
    public string Hash(string password)
    {
        Guard.NotWhiteSpace(password);
        var salt = RandomNumberGenerator.GetBytes(16);
        var derived = DeriveKey(password, salt, _iterations);
        return string.Join('$', "pbkdf2_sha256", _iterations.ToString(), Convert.ToBase64String(salt), Convert.ToBase64String(derived));
    }

    /// <summary>Whether <paramref name="password"/> is the one <paramref name="stored"/> was made from. <see langword="false"/> on a hash of another form.</summary>
    public bool Verify(string password, string? stored)
    {
        if (string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(stored))
            return false;
        var parts = stored.Split('$');
        if (parts.Length != 4 || !string.Equals(parts[0], "pbkdf2_sha256", StringComparison.OrdinalIgnoreCase) || !int.TryParse(parts[1], out var iterations))
            return false;
        byte[] salt;
        byte[] expected;
        try
        {
            salt = Convert.FromBase64String(parts[2]);
            expected = Convert.FromBase64String(parts[3]);
        }
        catch (FormatException)
        {
            return false;
        }
        return CryptographicOperations.FixedTimeEquals(expected, DeriveKey(password, salt, iterations));
    }

    /// <summary>
    /// <see cref="Verify"/>, against a stand-in hash when <paramref name="storedOrNull"/> is <see langword="null"/>:
    /// the attempt costs the same time whether the account exists or not, so that its duration tells nothing.
    /// </summary>
    public bool VerifyOrDummy(string password, string? storedOrNull) => Verify(password, storedOrNull ?? DummyStoredHash);

    private byte[] DeriveKey(string password, byte[] salt, int iterations)
        => Rfc2898DeriveBytes.Pbkdf2(password + _pepper, salt, iterations, HashAlgorithmName.SHA256, 32);
}

/// <summary>How strong a password is, in four steps.</summary>
public enum PasswordStrength
{
    /// <summary>Score under 25: not acceptable.</summary>
    Weak,

    /// <summary>Score from 25 to 54: marginal.</summary>
    Fair,

    /// <summary>Score from 55 to 79: good.</summary>
    Strong,

    /// <summary>Score from 80: excellent.</summary>
    VeryStrong,
}

/// <summary>What <see cref="PasswordStrengthEvaluator"/> says of a password.</summary>
public sealed class PasswordStrengthResult
{
    /// <summary>A score from 0 to 100.</summary>
    public required int Score { get; init; }

    /// <summary>The step the score falls in.</summary>
    public required PasswordStrength Strength { get; init; }

    /// <summary>Whether the password meets the <see cref="PasswordPolicy"/>.</summary>
    public bool MeetsPolicy => Violations.Count == 0;

    /// <summary>What the policy requires and the password lacks, written for the person.</summary>
    public required IReadOnlyList<string> Violations { get; init; }
}

/// <summary>
/// Checks a password against the <see cref="PasswordPolicy"/> and scores it: length up to 40 points, an
/// uppercase letter 15, a lowercase one 10, a digit 15, a special character 20.
/// </summary>
public sealed class PasswordStrengthEvaluator(IOptions<IdentityOptions> options)
{
    /// <summary>Evaluates <paramref name="password"/>.</summary>
    public PasswordStrengthResult Evaluate(string? password)
    {
        var value = password ?? "";
        var score = ComputeScore(value);
        return new PasswordStrengthResult { Score = score, Strength = ToStrength(score), Violations = Violations(value, options.Value.PasswordPolicy) };
    }

    /// <summary>The violations of the policy by <paramref name="password"/>, empty when it meets the policy.</summary>
    public IReadOnlyList<string> Violations(string? password) => Violations(password ?? "", options.Value.PasswordPolicy);

    private static int ComputeScore(string password)
    {
        var length = Math.Clamp((password.Length - 4) * 3, 0, 40);
        var upper = password.Any(char.IsUpper) ? 15 : 0;
        var lower = password.Any(char.IsLower) ? 10 : 0;
        var digit = password.Any(char.IsDigit) ? 15 : 0;
        var special = password.Any(c => !char.IsLetterOrDigit(c)) ? 20 : 0;
        return Math.Min(length + upper + lower + digit + special, 100);
    }

    private static List<string> Violations(string password, PasswordPolicy policy)
    {
        var violations = new List<string>();
        if (password.Length < policy.MinLength)
            violations.Add($"At least {policy.MinLength} characters are required.");
        if (password.Length > policy.MaxLength)
            violations.Add($"At most {policy.MaxLength} characters are allowed.");
        if (policy.RequireUppercase && !password.Any(char.IsUpper))
            violations.Add("An uppercase letter is required.");
        if (policy.RequireLowercase && !password.Any(char.IsLower))
            violations.Add("A lowercase letter is required.");
        if (policy.RequireDigit && !password.Any(char.IsDigit))
            violations.Add("A digit is required.");
        if (policy.RequireSpecialChar && !password.Any(c => !char.IsLetterOrDigit(c)))
            violations.Add("A character that is neither a letter nor a digit is required.");
        return violations;
    }

    private static PasswordStrength ToStrength(int score) => score switch
    {
        < 25 => PasswordStrength.Weak,
        < 55 => PasswordStrength.Fair,
        < 80 => PasswordStrength.Strong,
        _ => PasswordStrength.VeryStrong,
    };
}

/// <summary>
/// Generates random passwords that meet the <see cref="PasswordPolicy"/>, from pools without the characters that
/// read alike (0 and O, 1, l and I), with the randomness of <see cref="RandomNumberGenerator"/>.
/// </summary>
public sealed class PasswordGenerator(IOptions<IdentityOptions> options)
{
    private const string LowercasePool = "abcdefghjkmnpqrstuvwxyz";
    private const string UppercasePool = "ABCDEFGHJKMNPQRSTUVWXYZ";
    private const string DigitPool = "23456789";
    private const string SpecialPool = "!@#$%^&*()-_=+[]{}|;:,.<>?";
    private const string FullPool = LowercasePool + UppercasePool + DigitPool + SpecialPool;

    /// <summary>
    /// Generates a password of <paramref name="length"/> characters, clamped to the policy's bounds; of twelve,
    /// clamped the same way, when <paramref name="length"/> is 0.
    /// </summary>
    public string Generate(int length = 0)
    {
        var policy = options.Value.PasswordPolicy;
        var effective = Math.Clamp(length > 0 ? length : 12, policy.MinLength, policy.MaxLength);

        var mandatory = new List<char>();
        if (policy.RequireLowercase) mandatory.Add(Pick(LowercasePool));
        if (policy.RequireUppercase) mandatory.Add(Pick(UppercasePool));
        if (policy.RequireDigit) mandatory.Add(Pick(DigitPool));
        if (policy.RequireSpecialChar) mandatory.Add(Pick(SpecialPool));

        var result = new char[effective];
        for (var i = 0; i < Math.Min(mandatory.Count, effective); i++)
            result[i] = mandatory[i];
        for (var i = mandatory.Count; i < effective; i++)
            result[i] = Pick(FullPool);
        for (var i = result.Length - 1; i > 0; i--)
        {
            var j = RandomNumberGenerator.GetInt32(i + 1);
            (result[i], result[j]) = (result[j], result[i]);
        }
        return new string(result);
    }

    private static char Pick(string pool) => pool[RandomNumberGenerator.GetInt32(pool.Length)];
}
