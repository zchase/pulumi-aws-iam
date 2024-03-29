// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "./utilities";

export class ReadOnlyPolicy extends pulumi.ComponentResource {
    /** @internal */
    public static readonly __pulumiType = 'aws-iam:index:ReadOnlyPolicy';

    /**
     * Returns true if the given object is an instance of ReadOnlyPolicy.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ReadOnlyPolicy {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ReadOnlyPolicy.__pulumiType;
    }

    /**
     * The ARN assigned by AWS to this policy.
     */
    public /*out*/ readonly arn!: pulumi.Output<string>;
    /**
     * The description of the policy.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * The policy's ID.
     */
    public /*out*/ readonly id!: pulumi.Output<string>;
    /**
     * The name of the policy.
     */
    public readonly name!: pulumi.Output<string>;
    /**
     * The path of the policy in IAM.
     */
    public readonly path!: pulumi.Output<string>;
    /**
     * The policy document.
     */
    public /*out*/ readonly policy!: pulumi.Output<string>;
    /**
     * Policy document as json. Useful if you need document but do not want to create IAM policy itself. For example for SSO Permission Set inline policies.
     */
    public /*out*/ readonly policyJson!: pulumi.Output<string>;

    /**
     * Create a ReadOnlyPolicy resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ReadOnlyPolicyArgs, opts?: pulumi.ComponentResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (!opts.id) {
            if ((!args || args.name === undefined) && !opts.urn) {
                throw new Error("Missing required property 'name'");
            }
            resourceInputs["additionalPolicyJson"] = (args ? args.additionalPolicyJson : undefined) ?? "{}";
            resourceInputs["allowCloudwatchLogsQuery"] = (args ? args.allowCloudwatchLogsQuery : undefined) ?? true;
            resourceInputs["allowPredefinedStsActions"] = (args ? args.allowPredefinedStsActions : undefined) ?? true;
            resourceInputs["allowWebConsoleServices"] = (args ? args.allowWebConsoleServices : undefined) ?? true;
            resourceInputs["allowedServices"] = args ? args.allowedServices : undefined;
            resourceInputs["description"] = (args ? args.description : undefined) ?? "IAM Policy";
            resourceInputs["name"] = args ? args.name : undefined;
            resourceInputs["path"] = (args ? args.path : undefined) ?? "/";
            resourceInputs["tags"] = args ? args.tags : undefined;
            resourceInputs["webConsoleServices"] = args ? args.webConsoleServices : undefined;
            resourceInputs["arn"] = undefined /*out*/;
            resourceInputs["id"] = undefined /*out*/;
            resourceInputs["policy"] = undefined /*out*/;
            resourceInputs["policyJson"] = undefined /*out*/;
        } else {
            resourceInputs["arn"] = undefined /*out*/;
            resourceInputs["description"] = undefined /*out*/;
            resourceInputs["id"] = undefined /*out*/;
            resourceInputs["name"] = undefined /*out*/;
            resourceInputs["path"] = undefined /*out*/;
            resourceInputs["policy"] = undefined /*out*/;
            resourceInputs["policyJson"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ReadOnlyPolicy.__pulumiType, name, resourceInputs, opts, true /*remote*/);
    }
}

/**
 * The set of arguments for constructing a ReadOnlyPolicy resource.
 */
export interface ReadOnlyPolicyArgs {
    /**
     * JSON policy document if you want to add custom actions.
     */
    additionalPolicyJson?: pulumi.Input<string>;
    /**
     * Allows StartQuery/StopQuery/FilterLogEvents CloudWatch actions.
     */
    allowCloudwatchLogsQuery?: pulumi.Input<boolean>;
    /**
     * Allows GetCallerIdentity/GetSessionToken/GetAccessKeyInfo sts actions.
     */
    allowPredefinedStsActions?: pulumi.Input<boolean>;
    /**
     * Allows List/Get/Describe/View actions for services used when browsing AWS console (e.g. resource-groups, tag, health services).
     */
    allowWebConsoleServices?: pulumi.Input<boolean>;
    /**
     * List of services to allow Get/List/Describe/View options. Service name should be the same as corresponding service IAM prefix. See what it is for each service here https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html.
     */
    allowedServices?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The description of the policy.
     */
    description?: pulumi.Input<string>;
    /**
     * The name of the policy.
     */
    name: pulumi.Input<string>;
    /**
     * The path of the policy in IAM.
     */
    path?: pulumi.Input<string>;
    /**
     * A map of tags to add.
     */
    tags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * List of web console services to allow.
     */
    webConsoleServices?: pulumi.Input<pulumi.Input<string>[]>;
}
