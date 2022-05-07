// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.AwsIam.Inputs
{

    /// <summary>
    /// The admin role.
    /// </summary>
    public sealed class AdminRoleArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// IAM role with admin access.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// Path of admin IAM role.
        /// </summary>
        [Input("path")]
        public Input<string>? Path { get; set; }

        /// <summary>
        /// Permissions boundary ARN to use for admin role.
        /// </summary>
        [Input("permissionsBoundaryArn")]
        public Input<string>? PermissionsBoundaryArn { get; set; }

        [Input("policyArns")]
        private InputList<string>? _policyArns;

        /// <summary>
        /// List of policy ARNs to use for admin role.
        /// </summary>
        public InputList<string> PolicyArns
        {
            get => _policyArns ?? (_policyArns = new InputList<string>());
            set => _policyArns = value;
        }

        [Input("tags")]
        public Input<Inputs.TagsArgs>? Tags { get; set; }

        public AdminRoleArgs()
        {
            Name = "admin";
            Path = "/";
            PermissionsBoundaryArn = "";
        }
    }
}
