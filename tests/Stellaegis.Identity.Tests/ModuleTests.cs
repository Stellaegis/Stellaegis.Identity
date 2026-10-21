using Stellaegis.Primitives;

namespace Stellaegis.Identity.Tests;

/// <summary>What the module declares, read against the frames an application may have.</summary>
public sealed class ModuleTests
{
    [Fact]
    public void The_module_has_no_compartments_and_fits_every_frame()
    {
        ApplicationFrame.WithoutCompartments.Validate([IdentityModule.Declaration]);
        ApplicationFrame.SingleCompartment("acme").Validate([IdentityModule.Declaration]);
        ApplicationFrame.ManyCompartments().WithSharedSpace().Validate([IdentityModule.Declaration]);

        Assert.Equal("identity", IdentityModule.Name);
        Assert.Equal(ModuleCompartments.None, IdentityModule.Declaration.Compartments);
        Assert.False(IdentityModule.Declaration.AcceptsSharedSpace);
        Assert.Equal(["users.read", "users.write", "users.delete", "security.read"], IdentityModule.Declaration.Operations.Select(o => o.Identity));
        Assert.Equal(IdentityModule.Declaration.Operations, IdentityOperations.All);
    }
}
