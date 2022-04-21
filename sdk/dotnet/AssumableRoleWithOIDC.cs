// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.AwsIam
{
    [AwsIamResourceType("aws-iam:index:AssumableRoleWithOIDC")]
    public partial class AssumableRoleWithOIDC : Pulumi.ComponentResource
    {
        /// <summary>
        /// ARN of IAM role.
        /// </summary>
        [Output("iamRoleArn")]
        public Output<string> IamRoleArn { get; private set; } = null!;

        /// <summary>
        /// Name of IAM role.
        /// </summary>
        [Output("iamRoleName")]
        public Output<string> IamRoleName { get; private set; } = null!;

        /// <summary>
        /// Path of IAM role.
        /// </summary>
        [Output("iamRolePath")]
        public Output<string> IamRolePath { get; private set; } = null!;

        /// <summary>
        /// Unique ID of IAM role.
        /// </summary>
        [Output("iamRoleUniqueId")]
        public Output<string> IamRoleUniqueId { get; private set; } = null!;


        /// <summary>
        /// Create a AssumableRoleWithOIDC resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public AssumableRoleWithOIDC(string name, AssumableRoleWithOIDCArgs? args = null, ComponentResourceOptions? options = null)
            : base("aws-iam:index:AssumableRoleWithOIDC", name, args ?? new AssumableRoleWithOIDCArgs(), MakeResourceOptions(options, ""), remote: true)
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

    public sealed class AssumableRoleWithOIDCArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The AWS account ID where the OIDC provider lives, leave empty to use the account for the AWS provider.
        /// </summary>
        [Input("awsAccountId")]
        public Input<string>? AwsAccountId { get; set; }

        /// <summary>
        /// Whether to create a role.
        /// </summary>
        [Input("createRole")]
        public Input<bool>? CreateRole { get; set; }

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

        /// <summary>
        /// Number of IAM policies to attach to IAM role.
        /// </summary>
        [Input("numberOfRolePolicyArns")]
        public Input<int>? NumberOfRolePolicyArns { get; set; }

        [Input("oidcFullyQualifiedAudiences")]
        private InputList<string>? _oidcFullyQualifiedAudiences;

        /// <summary>
        /// The audience to be added to the role policy. Set to sts.amazonaws.com for cross-account assumable role. Leave empty otherwise.
        /// </summary>
        public InputList<string> OidcFullyQualifiedAudiences
        {
            get => _oidcFullyQualifiedAudiences ?? (_oidcFullyQualifiedAudiences = new InputList<string>());
            set => _oidcFullyQualifiedAudiences = value;
        }

        [Input("oidcFullyQualifiedSubjects")]
        private InputList<string>? _oidcFullyQualifiedSubjects;

        /// <summary>
        /// The fully qualified OIDC subjects to be added to the role policy.
        /// </summary>
        public InputList<string> OidcFullyQualifiedSubjects
        {
            get => _oidcFullyQualifiedSubjects ?? (_oidcFullyQualifiedSubjects = new InputList<string>());
            set => _oidcFullyQualifiedSubjects = value;
        }

        [Input("oidcSubjectsWithWildcards")]
        private InputList<string>? _oidcSubjectsWithWildcards;

        /// <summary>
        /// The OIDC subject using wildcards to be added to the role policy.
        /// </summary>
        public InputList<string> OidcSubjectsWithWildcards
        {
            get => _oidcSubjectsWithWildcards ?? (_oidcSubjectsWithWildcards = new InputList<string>());
            set => _oidcSubjectsWithWildcards = value;
        }

        /// <summary>
        /// URL of the OIDC Provider. Use provider_urls to specify several URLs.
        /// </summary>
        [Input("providerUrl")]
        public Input<string>? ProviderUrl { get; set; }

        [Input("providerUrls")]
        private InputList<string>? _providerUrls;

        /// <summary>
        /// List of URLs of the OIDC Providers.
        /// </summary>
        public InputList<string> ProviderUrls
        {
            get => _providerUrls ?? (_providerUrls = new InputList<string>());
            set => _providerUrls = value;
        }

        /// <summary>
        /// IAM Role description.
        /// </summary>
        [Input("roleDescription")]
        public Input<string>? RoleDescription { get; set; }

        /// <summary>
        /// IAM role name.
        /// </summary>
        [Input("roleName")]
        public Input<string>? RoleName { get; set; }

        /// <summary>
        /// IAM role name prefix.
        /// </summary>
        [Input("roleNamePrefix")]
        public Input<string>? RoleNamePrefix { get; set; }

        /// <summary>
        /// Path of IAM role.
        /// </summary>
        [Input("rolePath")]
        public Input<string>? RolePath { get; set; }

        /// <summary>
        /// Permissions boundary ARN to use for IAM role.
        /// </summary>
        [Input("rolePermissionsBoundaryArn")]
        public Input<string>? RolePermissionsBoundaryArn { get; set; }

        [Input("rolePolicyArns")]
        private InputList<string>? _rolePolicyArns;

        /// <summary>
        /// List of ARNs of IAM policies to attach to IAM role.
        /// </summary>
        public InputList<string> RolePolicyArns
        {
            get => _rolePolicyArns ?? (_rolePolicyArns = new InputList<string>());
            set => _rolePolicyArns = value;
        }

        [Input("tags")]
        public Input<Inputs.TagsArgs>? Tags { get; set; }

        public AssumableRoleWithOIDCArgs()
        {
            AwsAccountId = "";
            CreateRole = false;
            ForceDetachPolicies = false;
            MaxSessionDuration = 3600;
            ProviderUrl = "";
            RoleDescription = "";
            RolePath = "/";
            RolePermissionsBoundaryArn = "";
        }
    }
}