// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.awsiam;

import com.pulumi.awsiam.AccountArgs;
import com.pulumi.awsiam.Utilities;
import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import java.lang.Boolean;
import java.lang.String;
import javax.annotation.Nullable;

@ResourceType(type="aws-iam:index:Account")
public class Account extends com.pulumi.resources.ComponentResource {
    /**
     * The AWS ARN associated with the calling entity.
     * 
     */
    @Export(name="arn", type=String.class, parameters={})
    private Output<String> arn;

    /**
     * @return The AWS ARN associated with the calling entity.
     * 
     */
    public Output<String> arn() {
        return this.arn;
    }
    /**
     * The AWS Account ID number of the account that owns or contains the calling entity.
     * 
     */
    @Export(name="id", type=String.class, parameters={})
    private Output<String> id;

    /**
     * @return The AWS Account ID number of the account that owns or contains the calling entity.
     * 
     */
    public Output<String> id() {
        return this.id;
    }
    /**
     * Indicates whether passwords in the account expire. Returns true if max password
     * age contains a value greater than 0. Returns false if it is 0 or not present.
     * 
     */
    @Export(name="passwordPolicyExpirePasswords", type=Boolean.class, parameters={})
    private Output<Boolean> passwordPolicyExpirePasswords;

    /**
     * @return Indicates whether passwords in the account expire. Returns true if max password
     * age contains a value greater than 0. Returns false if it is 0 or not present.
     * 
     */
    public Output<Boolean> passwordPolicyExpirePasswords() {
        return this.passwordPolicyExpirePasswords;
    }
    /**
     * The unique identifier of the calling entity.
     * 
     */
    @Export(name="userId", type=String.class, parameters={})
    private Output<String> userId;

    /**
     * @return The unique identifier of the calling entity.
     * 
     */
    public Output<String> userId() {
        return this.userId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public Account(String name) {
        this(name, AccountArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public Account(String name, AccountArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public Account(String name, AccountArgs args, @Nullable com.pulumi.resources.ComponentResourceOptions options) {
        super("aws-iam:index:Account", name, args == null ? AccountArgs.Empty : args, makeResourceOptions(options, Codegen.empty()), true);
    }

    private static com.pulumi.resources.ComponentResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.ComponentResourceOptions options, @Nullable Output<String> id) {
        var defaultOptions = com.pulumi.resources.ComponentResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.ComponentResourceOptions.merge(defaultOptions, options, id);
    }

}
