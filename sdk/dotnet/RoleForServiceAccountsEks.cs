// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.AwsIam
{
    [AwsIamResourceType("aws-iam:index:RoleForServiceAccountsEks")]
    public partial class RoleForServiceAccountsEks : Pulumi.ComponentResource
    {
        [Output("role")]
        public Output<ImmutableDictionary<string, string>> Role { get; private set; } = null!;


        /// <summary>
        /// Create a RoleForServiceAccountsEks resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public RoleForServiceAccountsEks(string name, RoleForServiceAccountsEksArgs? args = null, ComponentResourceOptions? options = null)
            : base("aws-iam:index:RoleForServiceAccountsEks", name, args ?? new RoleForServiceAccountsEksArgs(), MakeResourceOptions(options, ""), remote: true)
        {
        }

        private static ComponentResourceOptions MakeResourceOptions(ComponentResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new ComponentResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = ComponentResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
    }

    public sealed class RoleForServiceAccountsEksArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Name of the IAM condition operator to evaluate when assuming the role.
        /// </summary>
        [Input("assumeRoleConditionTest")]
        public Input<string>? AssumeRoleConditionTest { get; set; }

        /// <summary>
        /// Whether policies should be detached from this role when destroying.
        /// </summary>
        [Input("forceDetachPolicies")]
        public Input<bool>? ForceDetachPolicies { get; set; }

        /// <summary>
        /// Maximum CLI/API session duration in seconds between 3600 and 43200.
        /// </summary>
        [Input("maxSessionDuration")]
        public Input<int>? MaxSessionDuration { get; set; }

        [Input("oidcProviders")]
        private InputMap<Inputs.OIDCProviderArgs>? _oidcProviders;

        /// <summary>
        /// Map of OIDC providers.
        /// </summary>
        public InputMap<Inputs.OIDCProviderArgs> OidcProviders
        {
            get => _oidcProviders ?? (_oidcProviders = new InputMap<Inputs.OIDCProviderArgs>());
            set => _oidcProviders = value;
        }

        [Input("policies")]
        public Input<Inputs.EKSRolePoliciesArgs>? Policies { get; set; }

        /// <summary>
        /// IAM policy name prefix.
        /// </summary>
        [Input("policyNamePrefix")]
        public Input<string>? PolicyNamePrefix { get; set; }

        [Input("role")]
        public Input<Inputs.EKSServiceAccountRoleArgs>? Role { get; set; }

        [Input("tags")]
        private InputMap<string>? _tags;

        /// <summary>
        /// A map of tags to add.
        /// </summary>
        public InputMap<string> Tags
        {
            get => _tags ?? (_tags = new InputMap<string>());
            set => _tags = value;
        }

        public RoleForServiceAccountsEksArgs()
        {
            AssumeRoleConditionTest = "StringEquals";
            ForceDetachPolicies = false;
            MaxSessionDuration = 3600;
            PolicyNamePrefix = "AmazonEKS_";
        }
    }
}
