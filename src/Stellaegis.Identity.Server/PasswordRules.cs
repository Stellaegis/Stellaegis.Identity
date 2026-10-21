using Microsoft.Extensions.Options;

namespace Stellaegis.Identity.Server;

/// <summary>
/// The password policy of the module, read for the pages: the rules a person sees before typing, and the ones a
/// password broke, in the person's language. The module checks the policy again when it creates or changes the
/// password; this is the same policy, worded for a page.
/// </summary>
internal sealed class PasswordRules(IOptions<IdentityOptions> options, IdentityTexts texts)
{
    /// <summary>The rules of the policy, worded, to show under a password field.</summary>
    public IReadOnlyList<string> Describe()
    {
        var policy = options.Value.PasswordPolicy;
        var rules = new List<string> { texts.Format("Password.Rule.MinLength", policy.MinLength) };
        if (policy.RequireUppercase)
            rules.Add(texts["Password.Rule.Uppercase"]);
        if (policy.RequireLowercase)
            rules.Add(texts["Password.Rule.Lowercase"]);
        if (policy.RequireDigit)
            rules.Add(texts["Password.Rule.Digit"]);
        if (policy.RequireSpecialChar)
            rules.Add(texts["Password.Rule.Special"]);
        return rules;
    }

    /// <summary>The rules <paramref name="password"/> breaks, worded; empty when it meets the policy.</summary>
    public IReadOnlyList<string> Violations(string? password)
    {
        var policy = options.Value.PasswordPolicy;
        password ??= "";
        var violations = new List<string>();
        if (password.Length < policy.MinLength)
            violations.Add(texts.Format("Password.Rule.MinLength", policy.MinLength));
        if (password.Length > policy.MaxLength)
            violations.Add(texts.Format("Password.Rule.MaxLength", policy.MaxLength));
        if (policy.RequireUppercase && !password.Any(char.IsUpper))
            violations.Add(texts["Password.Rule.Uppercase"]);
        if (policy.RequireLowercase && !password.Any(char.IsLower))
            violations.Add(texts["Password.Rule.Lowercase"]);
        if (policy.RequireDigit && !password.Any(char.IsDigit))
            violations.Add(texts["Password.Rule.Digit"]);
        if (policy.RequireSpecialChar && !password.Any(c => !char.IsLetterOrDigit(c)))
            violations.Add(texts["Password.Rule.Special"]);
        return violations;
    }

    /// <summary>The policy, for the strength meter of a page.</summary>
    public PasswordPolicy Policy => options.Value.PasswordPolicy;
}
