// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.awsiam.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


/**
 * The Appmesh policies.
 * 
 */
public final class EKSAppmeshPolicyArgs extends com.pulumi.resources.ResourceArgs {

    public static final EKSAppmeshPolicyArgs Empty = new EKSAppmeshPolicyArgs();

    /**
     * Determines whether to attach the Appmesh Controller policy to the role.
     * 
     */
    @Import(name="controller")
    private @Nullable Output<Boolean> controller;

    /**
     * @return Determines whether to attach the Appmesh Controller policy to the role.
     * 
     */
    public Optional<Output<Boolean>> controller() {
        return Optional.ofNullable(this.controller);
    }

    /**
     * Determines whether to attach the Appmesh envoy proxy policy to the role.
     * 
     */
    @Import(name="envoyProxy")
    private @Nullable Output<Boolean> envoyProxy;

    /**
     * @return Determines whether to attach the Appmesh envoy proxy policy to the role.
     * 
     */
    public Optional<Output<Boolean>> envoyProxy() {
        return Optional.ofNullable(this.envoyProxy);
    }

    private EKSAppmeshPolicyArgs() {}

    private EKSAppmeshPolicyArgs(EKSAppmeshPolicyArgs $) {
        this.controller = $.controller;
        this.envoyProxy = $.envoyProxy;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(EKSAppmeshPolicyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private EKSAppmeshPolicyArgs $;

        public Builder() {
            $ = new EKSAppmeshPolicyArgs();
        }

        public Builder(EKSAppmeshPolicyArgs defaults) {
            $ = new EKSAppmeshPolicyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param controller Determines whether to attach the Appmesh Controller policy to the role.
         * 
         * @return builder
         * 
         */
        public Builder controller(@Nullable Output<Boolean> controller) {
            $.controller = controller;
            return this;
        }

        /**
         * @param controller Determines whether to attach the Appmesh Controller policy to the role.
         * 
         * @return builder
         * 
         */
        public Builder controller(Boolean controller) {
            return controller(Output.of(controller));
        }

        /**
         * @param envoyProxy Determines whether to attach the Appmesh envoy proxy policy to the role.
         * 
         * @return builder
         * 
         */
        public Builder envoyProxy(@Nullable Output<Boolean> envoyProxy) {
            $.envoyProxy = envoyProxy;
            return this;
        }

        /**
         * @param envoyProxy Determines whether to attach the Appmesh envoy proxy policy to the role.
         * 
         * @return builder
         * 
         */
        public Builder envoyProxy(Boolean envoyProxy) {
            return envoyProxy(Output.of(envoyProxy));
        }

        public EKSAppmeshPolicyArgs build() {
            return $;
        }
    }

}