// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.awsiam;

import com.pulumi.awsiam.AssumableRoleWithSAMLArgs;
import com.pulumi.awsiam.Utilities;
import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import java.lang.String;
import javax.annotation.Nullable;

@ResourceType(type="aws-iam:index:AssumableRoleWithSAML")
public class AssumableRoleWithSAML extends com.pulumi.resources.ComponentResource {
    /**
     * ARN of IAM role.
     * 
     */
    @Export(name="roleArn", type=String.class, parameters={})
    private Output<String> roleArn;

    /**
     * @return ARN of IAM role.
     * 
     */
    public Output<String> roleArn() {
        return this.roleArn;
    }
    /**
     * Name of IAM role.
     * 
     */
    @Export(name="roleName", type=String.class, parameters={})
    private Output<String> roleName;

    /**
     * @return Name of IAM role.
     * 
     */
    public Output<String> roleName() {
        return this.roleName;
    }
    /**
     * Path of IAM role.
     * 
     */
    @Export(name="rolePath", type=String.class, parameters={})
    private Output<String> rolePath;

    /**
     * @return Path of IAM role.
     * 
     */
    public Output<String> rolePath() {
        return this.rolePath;
    }
    /**
     * Unique ID of IAM role.
     * 
     */
    @Export(name="roleUniqueId", type=String.class, parameters={})
    private Output<String> roleUniqueId;

    /**
     * @return Unique ID of IAM role.
     * 
     */
    public Output<String> roleUniqueId() {
        return this.roleUniqueId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public AssumableRoleWithSAML(String name) {
        this(name, AssumableRoleWithSAMLArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public AssumableRoleWithSAML(String name, @Nullable AssumableRoleWithSAMLArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public AssumableRoleWithSAML(String name, @Nullable AssumableRoleWithSAMLArgs args, @Nullable com.pulumi.resources.ComponentResourceOptions options) {
        super("aws-iam:index:AssumableRoleWithSAML", name, args == null ? AssumableRoleWithSAMLArgs.Empty : args, makeResourceOptions(options, Codegen.empty()), true);
    }

    private static com.pulumi.resources.ComponentResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.ComponentResourceOptions options, @Nullable Output<String> id) {
        var defaultOptions = com.pulumi.resources.ComponentResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.ComponentResourceOptions.merge(defaultOptions, options, id);
    }

}
