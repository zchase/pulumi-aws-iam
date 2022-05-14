// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.awsiam.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


/**
 * The FSx for Lustre CSI Driver IAM policy to the role.
 * 
 */
public final class FSxLustreCSIPolicyArgs extends com.pulumi.resources.ResourceArgs {

    public static final FSxLustreCSIPolicyArgs Empty = new FSxLustreCSIPolicyArgs();

    /**
     * Determines whether to attach the FSx for Lustre CSI Driver IAM policy to the role.
     * 
     */
    @Import(name="attach", required=true)
    private Output<Boolean> attach;

    /**
     * @return Determines whether to attach the FSx for Lustre CSI Driver IAM policy to the role.
     * 
     */
    public Output<Boolean> attach() {
        return this.attach;
    }

    /**
     * Service role ARNs to allow FSx for Lustre CSI create and manage FSX for Lustre service linked roles. If not provided,
     * the default ARN &#34;arn:aws:iam::*:role/aws-service-role/s3.data-source.lustre.fsx.amazonaws.com/*&#34; will be applied.
     * 
     */
    @Import(name="serviceRoleArns")
    private @Nullable Output<List<String>> serviceRoleArns;

    /**
     * @return Service role ARNs to allow FSx for Lustre CSI create and manage FSX for Lustre service linked roles. If not provided,
     * the default ARN &#34;arn:aws:iam::*:role/aws-service-role/s3.data-source.lustre.fsx.amazonaws.com/*&#34; will be applied.
     * 
     */
    public Optional<Output<List<String>>> serviceRoleArns() {
        return Optional.ofNullable(this.serviceRoleArns);
    }

    private FSxLustreCSIPolicyArgs() {}

    private FSxLustreCSIPolicyArgs(FSxLustreCSIPolicyArgs $) {
        this.attach = $.attach;
        this.serviceRoleArns = $.serviceRoleArns;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(FSxLustreCSIPolicyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private FSxLustreCSIPolicyArgs $;

        public Builder() {
            $ = new FSxLustreCSIPolicyArgs();
        }

        public Builder(FSxLustreCSIPolicyArgs defaults) {
            $ = new FSxLustreCSIPolicyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param attach Determines whether to attach the FSx for Lustre CSI Driver IAM policy to the role.
         * 
         * @return builder
         * 
         */
        public Builder attach(Output<Boolean> attach) {
            $.attach = attach;
            return this;
        }

        /**
         * @param attach Determines whether to attach the FSx for Lustre CSI Driver IAM policy to the role.
         * 
         * @return builder
         * 
         */
        public Builder attach(Boolean attach) {
            return attach(Output.of(attach));
        }

        /**
         * @param serviceRoleArns Service role ARNs to allow FSx for Lustre CSI create and manage FSX for Lustre service linked roles. If not provided,
         * the default ARN &#34;arn:aws:iam::*:role/aws-service-role/s3.data-source.lustre.fsx.amazonaws.com/*&#34; will be applied.
         * 
         * @return builder
         * 
         */
        public Builder serviceRoleArns(@Nullable Output<List<String>> serviceRoleArns) {
            $.serviceRoleArns = serviceRoleArns;
            return this;
        }

        /**
         * @param serviceRoleArns Service role ARNs to allow FSx for Lustre CSI create and manage FSX for Lustre service linked roles. If not provided,
         * the default ARN &#34;arn:aws:iam::*:role/aws-service-role/s3.data-source.lustre.fsx.amazonaws.com/*&#34; will be applied.
         * 
         * @return builder
         * 
         */
        public Builder serviceRoleArns(List<String> serviceRoleArns) {
            return serviceRoleArns(Output.of(serviceRoleArns));
        }

        /**
         * @param serviceRoleArns Service role ARNs to allow FSx for Lustre CSI create and manage FSX for Lustre service linked roles. If not provided,
         * the default ARN &#34;arn:aws:iam::*:role/aws-service-role/s3.data-source.lustre.fsx.amazonaws.com/*&#34; will be applied.
         * 
         * @return builder
         * 
         */
        public Builder serviceRoleArns(String... serviceRoleArns) {
            return serviceRoleArns(List.of(serviceRoleArns));
        }

        public FSxLustreCSIPolicyArgs build() {
            $.attach = Objects.requireNonNull($.attach, "expected parameter 'attach' to be non-null");
            return $;
        }
    }

}
