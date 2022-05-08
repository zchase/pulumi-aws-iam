// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.AwsIam
{
    [AwsIamResourceType("aws-iam:index:GroupWithAssumableRolesPolicy")]
    public partial class GroupWithAssumableRolesPolicy : Pulumi.ComponentResource
    {
        /// <summary>
        /// List of IAM roles ARNs which can be assumed by the group
        /// </summary>
        [Output("assumableRoles")]
        public Output<ImmutableArray<string>> AssumableRoles { get; private set; } = null!;

        /// <summary>
        /// IAM group arn.
        /// </summary>
        [Output("groupArn")]
        public Output<string> GroupArn { get; private set; } = null!;

        /// <summary>
        /// IAM group name.
        /// </summary>
        [Output("groupName")]
        public Output<string> GroupName { get; private set; } = null!;

        /// <summary>
        /// List of IAM users in IAM group
        /// </summary>
        [Output("groupUsers")]
        public Output<ImmutableArray<string>> GroupUsers { get; private set; } = null!;

        /// <summary>
        /// Assume role policy ARN of IAM group
        /// </summary>
        [Output("policyArn")]
        public Output<string> PolicyArn { get; private set; } = null!;


        /// <summary>
        /// Create a GroupWithAssumableRolesPolicy resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public GroupWithAssumableRolesPolicy(string name, GroupWithAssumableRolesPolicyArgs args, ComponentResourceOptions? options = null)
            : base("aws-iam:index:GroupWithAssumableRolesPolicy", name, args ?? new GroupWithAssumableRolesPolicyArgs(), MakeResourceOptions(options, ""), remote: true)
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

    public sealed class GroupWithAssumableRolesPolicyArgs : Pulumi.ResourceArgs
    {
        [Input("assumableRoles", required: true)]
        private InputList<string>? _assumableRoles;

        /// <summary>
        /// List of IAM roles ARNs which can be assumed by the group
        /// </summary>
        public InputList<string> AssumableRoles
        {
            get => _assumableRoles ?? (_assumableRoles = new InputList<string>());
            set => _assumableRoles = value;
        }

        [Input("groupUsers", required: true)]
        private InputList<string>? _groupUsers;

        /// <summary>
        /// List of IAM users to have in an IAM group which can assume the role
        /// </summary>
        public InputList<string> GroupUsers
        {
            get => _groupUsers ?? (_groupUsers = new InputList<string>());
            set => _groupUsers = value;
        }

        /// <summary>
        /// Name of IAM policy and IAM group.
        /// </summary>
        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

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

        public GroupWithAssumableRolesPolicyArgs()
        {
        }
    }
}
