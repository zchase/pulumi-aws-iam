// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "./utilities";

export class GroupWithAssumableRolesPolicy extends pulumi.ComponentResource {
    /** @internal */
    public static readonly __pulumiType = 'aws-iam:index:GroupWithAssumableRolesPolicy';

    /**
     * Returns true if the given object is an instance of GroupWithAssumableRolesPolicy.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is GroupWithAssumableRolesPolicy {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === GroupWithAssumableRolesPolicy.__pulumiType;
    }

    /**
     * List of IAM roles ARNs which can be assumed by the group
     */
    public readonly assumableRoles!: pulumi.Output<string[]>;
    /**
     * IAM group arn.
     */
    public /*out*/ readonly groupArn!: pulumi.Output<string>;
    /**
     * IAM group name.
     */
    public /*out*/ readonly groupName!: pulumi.Output<string>;
    /**
     * List of IAM users in IAM group
     */
    public readonly groupUsers!: pulumi.Output<string[]>;
    /**
     * Assume role policy ARN of IAM group
     */
    public /*out*/ readonly policyArn!: pulumi.Output<string>;

    /**
     * Create a GroupWithAssumableRolesPolicy resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: GroupWithAssumableRolesPolicyArgs, opts?: pulumi.ComponentResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (!opts.id) {
            if ((!args || args.assumableRoles === undefined) && !opts.urn) {
                throw new Error("Missing required property 'assumableRoles'");
            }
            if ((!args || args.groupUsers === undefined) && !opts.urn) {
                throw new Error("Missing required property 'groupUsers'");
            }
            if ((!args || args.name === undefined) && !opts.urn) {
                throw new Error("Missing required property 'name'");
            }
            resourceInputs["assumableRoles"] = args ? args.assumableRoles : undefined;
            resourceInputs["groupUsers"] = args ? args.groupUsers : undefined;
            resourceInputs["name"] = args ? args.name : undefined;
            resourceInputs["tags"] = args ? args.tags : undefined;
            resourceInputs["groupArn"] = undefined /*out*/;
            resourceInputs["groupName"] = undefined /*out*/;
            resourceInputs["policyArn"] = undefined /*out*/;
        } else {
            resourceInputs["assumableRoles"] = undefined /*out*/;
            resourceInputs["groupArn"] = undefined /*out*/;
            resourceInputs["groupName"] = undefined /*out*/;
            resourceInputs["groupUsers"] = undefined /*out*/;
            resourceInputs["policyArn"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(GroupWithAssumableRolesPolicy.__pulumiType, name, resourceInputs, opts, true /*remote*/);
    }
}

/**
 * The set of arguments for constructing a GroupWithAssumableRolesPolicy resource.
 */
export interface GroupWithAssumableRolesPolicyArgs {
    /**
     * List of IAM roles ARNs which can be assumed by the group
     */
    assumableRoles: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of IAM users to have in an IAM group which can assume the role
     */
    groupUsers: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Name of IAM policy and IAM group.
     */
    name: pulumi.Input<string>;
    /**
     * A map of tags to add.
     */
    tags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
}
