// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.awsiam;

import com.pulumi.awsiam.RoleForServiceAccountsEksArgs;
import com.pulumi.awsiam.Utilities;
import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import java.lang.String;
import java.util.Map;
import javax.annotation.Nullable;

@ResourceType(type="aws-iam:index:RoleForServiceAccountsEks")
public class RoleForServiceAccountsEks extends com.pulumi.resources.ComponentResource {
    @Export(name="role", type=Map.class, parameters={String.class, String.class})
    private Output<Map<String,String>> role;

    public Output<Map<String,String>> role() {
        return this.role;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public RoleForServiceAccountsEks(String name) {
        this(name, RoleForServiceAccountsEksArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public RoleForServiceAccountsEks(String name, @Nullable RoleForServiceAccountsEksArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public RoleForServiceAccountsEks(String name, @Nullable RoleForServiceAccountsEksArgs args, @Nullable com.pulumi.resources.ComponentResourceOptions options) {
        super("aws-iam:index:RoleForServiceAccountsEks", name, args == null ? RoleForServiceAccountsEksArgs.Empty : args, makeResourceOptions(options, Codegen.empty()), true);
    }

    private static com.pulumi.resources.ComponentResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.ComponentResourceOptions options, @Nullable Output<String> id) {
        var defaultOptions = com.pulumi.resources.ComponentResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.ComponentResourceOptions.merge(defaultOptions, options, id);
    }

}
