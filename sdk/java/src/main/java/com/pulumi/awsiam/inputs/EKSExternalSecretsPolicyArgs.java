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
 * The External Secrets policy to the role.
 * 
 */
public final class EKSExternalSecretsPolicyArgs extends com.pulumi.resources.ResourceArgs {

    public static final EKSExternalSecretsPolicyArgs Empty = new EKSExternalSecretsPolicyArgs();

    /**
     * Determines whether to attach the External Secrets policy to the role.
     * 
     */
    @Import(name="attach", required=true)
    private Output<Boolean> attach;

    /**
     * @return Determines whether to attach the External Secrets policy to the role.
     * 
     */
    public Output<Boolean> attach() {
        return this.attach;
    }

    /**
     * List of Secrets Manager ARNs that contain secrets to mount using External Secrets. If not provided, the default ARN &#34;arn:aws:secretsmanager:*:*:secret:*&#34; will be applied.
     * 
     */
    @Import(name="secretsManagerArns")
    private @Nullable Output<List<String>> secretsManagerArns;

    /**
     * @return List of Secrets Manager ARNs that contain secrets to mount using External Secrets. If not provided, the default ARN &#34;arn:aws:secretsmanager:*:*:secret:*&#34; will be applied.
     * 
     */
    public Optional<Output<List<String>>> secretsManagerArns() {
        return Optional.ofNullable(this.secretsManagerArns);
    }

    /**
     * List of Systems Manager Parameter ARNs that contain secrets to mount using External Secrets. If not provided,
     * the default ARN &#34;arn:aws:ssm:*:*:parameter/*&#34; will be applied.
     * 
     */
    @Import(name="ssmParameterArns")
    private @Nullable Output<List<String>> ssmParameterArns;

    /**
     * @return List of Systems Manager Parameter ARNs that contain secrets to mount using External Secrets. If not provided,
     * the default ARN &#34;arn:aws:ssm:*:*:parameter/*&#34; will be applied.
     * 
     */
    public Optional<Output<List<String>>> ssmParameterArns() {
        return Optional.ofNullable(this.ssmParameterArns);
    }

    private EKSExternalSecretsPolicyArgs() {}

    private EKSExternalSecretsPolicyArgs(EKSExternalSecretsPolicyArgs $) {
        this.attach = $.attach;
        this.secretsManagerArns = $.secretsManagerArns;
        this.ssmParameterArns = $.ssmParameterArns;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(EKSExternalSecretsPolicyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private EKSExternalSecretsPolicyArgs $;

        public Builder() {
            $ = new EKSExternalSecretsPolicyArgs();
        }

        public Builder(EKSExternalSecretsPolicyArgs defaults) {
            $ = new EKSExternalSecretsPolicyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param attach Determines whether to attach the External Secrets policy to the role.
         * 
         * @return builder
         * 
         */
        public Builder attach(Output<Boolean> attach) {
            $.attach = attach;
            return this;
        }

        /**
         * @param attach Determines whether to attach the External Secrets policy to the role.
         * 
         * @return builder
         * 
         */
        public Builder attach(Boolean attach) {
            return attach(Output.of(attach));
        }

        /**
         * @param secretsManagerArns List of Secrets Manager ARNs that contain secrets to mount using External Secrets. If not provided, the default ARN &#34;arn:aws:secretsmanager:*:*:secret:*&#34; will be applied.
         * 
         * @return builder
         * 
         */
        public Builder secretsManagerArns(@Nullable Output<List<String>> secretsManagerArns) {
            $.secretsManagerArns = secretsManagerArns;
            return this;
        }

        /**
         * @param secretsManagerArns List of Secrets Manager ARNs that contain secrets to mount using External Secrets. If not provided, the default ARN &#34;arn:aws:secretsmanager:*:*:secret:*&#34; will be applied.
         * 
         * @return builder
         * 
         */
        public Builder secretsManagerArns(List<String> secretsManagerArns) {
            return secretsManagerArns(Output.of(secretsManagerArns));
        }

        /**
         * @param secretsManagerArns List of Secrets Manager ARNs that contain secrets to mount using External Secrets. If not provided, the default ARN &#34;arn:aws:secretsmanager:*:*:secret:*&#34; will be applied.
         * 
         * @return builder
         * 
         */
        public Builder secretsManagerArns(String... secretsManagerArns) {
            return secretsManagerArns(List.of(secretsManagerArns));
        }

        /**
         * @param ssmParameterArns List of Systems Manager Parameter ARNs that contain secrets to mount using External Secrets. If not provided,
         * the default ARN &#34;arn:aws:ssm:*:*:parameter/*&#34; will be applied.
         * 
         * @return builder
         * 
         */
        public Builder ssmParameterArns(@Nullable Output<List<String>> ssmParameterArns) {
            $.ssmParameterArns = ssmParameterArns;
            return this;
        }

        /**
         * @param ssmParameterArns List of Systems Manager Parameter ARNs that contain secrets to mount using External Secrets. If not provided,
         * the default ARN &#34;arn:aws:ssm:*:*:parameter/*&#34; will be applied.
         * 
         * @return builder
         * 
         */
        public Builder ssmParameterArns(List<String> ssmParameterArns) {
            return ssmParameterArns(Output.of(ssmParameterArns));
        }

        /**
         * @param ssmParameterArns List of Systems Manager Parameter ARNs that contain secrets to mount using External Secrets. If not provided,
         * the default ARN &#34;arn:aws:ssm:*:*:parameter/*&#34; will be applied.
         * 
         * @return builder
         * 
         */
        public Builder ssmParameterArns(String... ssmParameterArns) {
            return ssmParameterArns(List.of(ssmParameterArns));
        }

        public EKSExternalSecretsPolicyArgs build() {
            $.attach = Objects.requireNonNull($.attach, "expected parameter 'attach' to be non-null");
            return $;
        }
    }

}