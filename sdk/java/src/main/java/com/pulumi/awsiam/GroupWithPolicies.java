// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.awsiam;

import com.pulumi.awsiam.GroupWithPoliciesArgs;
import com.pulumi.awsiam.Utilities;
import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import java.lang.String;
import java.util.List;
import javax.annotation.Nullable;

@ResourceType(type="aws-iam:index:GroupWithPolicies")
public class GroupWithPolicies extends com.pulumi.resources.ComponentResource {
    /**
     * IAM AWS account id.
     * 
     */
    @Export(name="awsAccountId", type=String.class, parameters={})
    private Output<String> awsAccountId;

    /**
     * @return IAM AWS account id.
     * 
     */
    public Output<String> awsAccountId() {
        return this.awsAccountId;
    }
    /**
     * IAM group arn.
     * 
     */
    @Export(name="groupArn", type=String.class, parameters={})
    private Output<String> groupArn;

    /**
     * @return IAM group arn.
     * 
     */
    public Output<String> groupArn() {
        return this.groupArn;
    }
    /**
     * IAM group name.
     * 
     */
    @Export(name="groupName", type=String.class, parameters={})
    private Output<String> groupName;

    /**
     * @return IAM group name.
     * 
     */
    public Output<String> groupName() {
        return this.groupName;
    }
    /**
     * List of IAM users in IAM group
     * 
     */
    @Export(name="groupUsers", type=List.class, parameters={String.class})
    private Output<List<String>> groupUsers;

    /**
     * @return List of IAM users in IAM group
     * 
     */
    public Output<List<String>> groupUsers() {
        return this.groupUsers;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public GroupWithPolicies(String name) {
        this(name, GroupWithPoliciesArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public GroupWithPolicies(String name, GroupWithPoliciesArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public GroupWithPolicies(String name, GroupWithPoliciesArgs args, @Nullable com.pulumi.resources.ComponentResourceOptions options) {
        super("aws-iam:index:GroupWithPolicies", name, args == null ? GroupWithPoliciesArgs.Empty : args, makeResourceOptions(options, Codegen.empty()), true);
    }

    private static com.pulumi.resources.ComponentResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.ComponentResourceOptions options, @Nullable Output<String> id) {
        var defaultOptions = com.pulumi.resources.ComponentResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.ComponentResourceOptions.merge(defaultOptions, options, id);
    }

}
