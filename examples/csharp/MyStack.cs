using Pulumi;
using Pulumi.AwsIam;
using Pulumi.AwsIam.Inputs;

class MyStack : Stack
{
    public MyStack()
    {
        // Account
        var account = new Account("account", new AccountArgs
        {
            AccountAlias = "cool-alias",
            MinimumPasswordLength = 37,
            RequireNumbers = false,
        });

        this.Account = Output.Create<Account>(account);

        // Assumable Role
        var assumableRole = new AssumableRole("assumable-role", new AssumableRoleArgs
        {
            TrustedRoleArns = {"arn:aws:iam::307990089504:root", "arn:aws:iam::835367859851:user/pulumipus"},
            CustomRolePolicyArns = {"arn:aws:iam::aws:policy/AmazonCognitoReadOnly","arn:aws:iam::aws:policy/AlexaForBusinessFullAccess"},
            Role = new RoleWithMFAArgs
            {
                Name = "custom",
                RequiresMfa = true,
            },
        });

        this.AssumableRole = Output.Create<AssumableRole>(assumableRole);

        // Assumable Role With OIDC
        var assumableRoleWithOidc = new AssumableRoleWithOIDC("assumable-role-with-oidc", new AssumableRoleWithOIDCArgs
        {
            Role = new RoleArgs
            {
                Name = "oidc-role",
                PolicyArns = {"arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"},
            },
            Tags = new InputMap<string>{},
        });
    }

    [Output]
    public Output<Account> Account { get; set; }

    [Output]
    public Output<AssumableRole> AssumableRole { get; set; }

    [Output]
    public Output<AssumableRoleWithOIDC> AssumableRoleWithOidc { get; set; }

    [Output]
    public Output<AssumableRoleWithSAML> AssumableRoleWithSaml { get; set; }

    [Output]
    public Output<AssumableRoles> AssumableRoles { get; set; }

    [Output]
    public Output<AssumableRolesWithSAML> AssumableRolesWithSaml { get; set; }

    [Output]
    public Output<EKSRole> EksRole { get; set; }

    [Output]
    public Output<GroupWithAssumableRolesPolicy> GroupWithAssumableRolesPolicy { get; set; }

    [Output]
    public Output<GroupWithPolicies> GroupWithPolicies { get; set; }

    [Output]
    public Output<Policy> Policy { get; set; }

    [Output]
    public Output<ReadOnlyPolicy> ReadOnlyPolicy { get; set; }

    [Output]
    public Output<RoleForServiceAccountsEks> RoleForServiceAccountEks { get; set; }

    [Output]
    public Output<User> User { get; set; }
}
