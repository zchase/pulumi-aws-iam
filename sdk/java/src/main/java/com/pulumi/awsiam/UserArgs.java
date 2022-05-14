// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.awsiam;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.core.internal.Codegen;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class UserArgs extends com.pulumi.resources.ResourceArgs {

    public static final UserArgs Empty = new UserArgs();

    /**
     * When destroying this user, destroy even if it has non-Pulumi-managed IAM access keys, login profile or MFA devices. Without forceDestroy a user with non-Pulumi-managed access keys and login profile will fail to be destroyed.
     * 
     */
    @Import(name="forceDestroy")
    private @Nullable Output<Boolean> forceDestroy;

    /**
     * @return When destroying this user, destroy even if it has non-Pulumi-managed IAM access keys, login profile or MFA devices. Without forceDestroy a user with non-Pulumi-managed access keys and login profile will fail to be destroyed.
     * 
     */
    public Optional<Output<Boolean>> forceDestroy() {
        return Optional.ofNullable(this.forceDestroy);
    }

    /**
     * Desired name for the IAM user.
     * 
     */
    @Import(name="name", required=true)
    private Output<String> name;

    /**
     * @return Desired name for the IAM user.
     * 
     */
    public Output<String> name() {
        return this.name;
    }

    /**
     * The length of the generated password
     * 
     */
    @Import(name="passwordLength")
    private @Nullable Output<Integer> passwordLength;

    /**
     * @return The length of the generated password
     * 
     */
    public Optional<Output<Integer>> passwordLength() {
        return Optional.ofNullable(this.passwordLength);
    }

    /**
     * Whether the user should be forced to reset the generated password on first login.
     * 
     */
    @Import(name="passwordResetRequired")
    private @Nullable Output<Boolean> passwordResetRequired;

    /**
     * @return Whether the user should be forced to reset the generated password on first login.
     * 
     */
    public Optional<Output<Boolean>> passwordResetRequired() {
        return Optional.ofNullable(this.passwordResetRequired);
    }

    /**
     * Desired path for the IAM user.
     * 
     */
    @Import(name="path")
    private @Nullable Output<String> path;

    /**
     * @return Desired path for the IAM user.
     * 
     */
    public Optional<Output<String>> path() {
        return Optional.ofNullable(this.path);
    }

    /**
     * The ARN of the policy that is used to set the permissions boundary for the user.
     * 
     */
    @Import(name="permissionsBoundary")
    private @Nullable Output<String> permissionsBoundary;

    /**
     * @return The ARN of the policy that is used to set the permissions boundary for the user.
     * 
     */
    public Optional<Output<String>> permissionsBoundary() {
        return Optional.ofNullable(this.permissionsBoundary);
    }

    /**
     * Either a base-64 encoded PGP public key, or a keybase username in the form `keybase:username`. Used to encrypt password and access key.
     * 
     */
    @Import(name="pgpKey")
    private @Nullable Output<String> pgpKey;

    /**
     * @return Either a base-64 encoded PGP public key, or a keybase username in the form `keybase:username`. Used to encrypt password and access key.
     * 
     */
    public Optional<Output<String>> pgpKey() {
        return Optional.ofNullable(this.pgpKey);
    }

    /**
     * Specifies the public key encoding format to use in the response. To retrieve the public key in ssh-rsa format, use SSH. To retrieve the public key in PEM format, use PEM.
     * 
     */
    @Import(name="sshKeyEncoding")
    private @Nullable Output<String> sshKeyEncoding;

    /**
     * @return Specifies the public key encoding format to use in the response. To retrieve the public key in ssh-rsa format, use SSH. To retrieve the public key in PEM format, use PEM.
     * 
     */
    public Optional<Output<String>> sshKeyEncoding() {
        return Optional.ofNullable(this.sshKeyEncoding);
    }

    /**
     * The SSH public key. The public key must be encoded in ssh-rsa format or PEM format.
     * 
     */
    @Import(name="sshPublicKey")
    private @Nullable Output<String> sshPublicKey;

    /**
     * @return The SSH public key. The public key must be encoded in ssh-rsa format or PEM format.
     * 
     */
    public Optional<Output<String>> sshPublicKey() {
        return Optional.ofNullable(this.sshPublicKey);
    }

    /**
     * A map of tags to add.
     * 
     */
    @Import(name="tags")
    private @Nullable Output<Map<String,String>> tags;

    /**
     * @return A map of tags to add.
     * 
     */
    public Optional<Output<Map<String,String>>> tags() {
        return Optional.ofNullable(this.tags);
    }

    /**
     * Whether to upload a public ssh key to the IAM user.
     * 
     */
    @Import(name="uploadIamUserSshKey")
    private @Nullable Output<Boolean> uploadIamUserSshKey;

    /**
     * @return Whether to upload a public ssh key to the IAM user.
     * 
     */
    public Optional<Output<Boolean>> uploadIamUserSshKey() {
        return Optional.ofNullable(this.uploadIamUserSshKey);
    }

    private UserArgs() {}

    private UserArgs(UserArgs $) {
        this.forceDestroy = $.forceDestroy;
        this.name = $.name;
        this.passwordLength = $.passwordLength;
        this.passwordResetRequired = $.passwordResetRequired;
        this.path = $.path;
        this.permissionsBoundary = $.permissionsBoundary;
        this.pgpKey = $.pgpKey;
        this.sshKeyEncoding = $.sshKeyEncoding;
        this.sshPublicKey = $.sshPublicKey;
        this.tags = $.tags;
        this.uploadIamUserSshKey = $.uploadIamUserSshKey;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(UserArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private UserArgs $;

        public Builder() {
            $ = new UserArgs();
        }

        public Builder(UserArgs defaults) {
            $ = new UserArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param forceDestroy When destroying this user, destroy even if it has non-Pulumi-managed IAM access keys, login profile or MFA devices. Without forceDestroy a user with non-Pulumi-managed access keys and login profile will fail to be destroyed.
         * 
         * @return builder
         * 
         */
        public Builder forceDestroy(@Nullable Output<Boolean> forceDestroy) {
            $.forceDestroy = forceDestroy;
            return this;
        }

        /**
         * @param forceDestroy When destroying this user, destroy even if it has non-Pulumi-managed IAM access keys, login profile or MFA devices. Without forceDestroy a user with non-Pulumi-managed access keys and login profile will fail to be destroyed.
         * 
         * @return builder
         * 
         */
        public Builder forceDestroy(Boolean forceDestroy) {
            return forceDestroy(Output.of(forceDestroy));
        }

        /**
         * @param name Desired name for the IAM user.
         * 
         * @return builder
         * 
         */
        public Builder name(Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name Desired name for the IAM user.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param passwordLength The length of the generated password
         * 
         * @return builder
         * 
         */
        public Builder passwordLength(@Nullable Output<Integer> passwordLength) {
            $.passwordLength = passwordLength;
            return this;
        }

        /**
         * @param passwordLength The length of the generated password
         * 
         * @return builder
         * 
         */
        public Builder passwordLength(Integer passwordLength) {
            return passwordLength(Output.of(passwordLength));
        }

        /**
         * @param passwordResetRequired Whether the user should be forced to reset the generated password on first login.
         * 
         * @return builder
         * 
         */
        public Builder passwordResetRequired(@Nullable Output<Boolean> passwordResetRequired) {
            $.passwordResetRequired = passwordResetRequired;
            return this;
        }

        /**
         * @param passwordResetRequired Whether the user should be forced to reset the generated password on first login.
         * 
         * @return builder
         * 
         */
        public Builder passwordResetRequired(Boolean passwordResetRequired) {
            return passwordResetRequired(Output.of(passwordResetRequired));
        }

        /**
         * @param path Desired path for the IAM user.
         * 
         * @return builder
         * 
         */
        public Builder path(@Nullable Output<String> path) {
            $.path = path;
            return this;
        }

        /**
         * @param path Desired path for the IAM user.
         * 
         * @return builder
         * 
         */
        public Builder path(String path) {
            return path(Output.of(path));
        }

        /**
         * @param permissionsBoundary The ARN of the policy that is used to set the permissions boundary for the user.
         * 
         * @return builder
         * 
         */
        public Builder permissionsBoundary(@Nullable Output<String> permissionsBoundary) {
            $.permissionsBoundary = permissionsBoundary;
            return this;
        }

        /**
         * @param permissionsBoundary The ARN of the policy that is used to set the permissions boundary for the user.
         * 
         * @return builder
         * 
         */
        public Builder permissionsBoundary(String permissionsBoundary) {
            return permissionsBoundary(Output.of(permissionsBoundary));
        }

        /**
         * @param pgpKey Either a base-64 encoded PGP public key, or a keybase username in the form `keybase:username`. Used to encrypt password and access key.
         * 
         * @return builder
         * 
         */
        public Builder pgpKey(@Nullable Output<String> pgpKey) {
            $.pgpKey = pgpKey;
            return this;
        }

        /**
         * @param pgpKey Either a base-64 encoded PGP public key, or a keybase username in the form `keybase:username`. Used to encrypt password and access key.
         * 
         * @return builder
         * 
         */
        public Builder pgpKey(String pgpKey) {
            return pgpKey(Output.of(pgpKey));
        }

        /**
         * @param sshKeyEncoding Specifies the public key encoding format to use in the response. To retrieve the public key in ssh-rsa format, use SSH. To retrieve the public key in PEM format, use PEM.
         * 
         * @return builder
         * 
         */
        public Builder sshKeyEncoding(@Nullable Output<String> sshKeyEncoding) {
            $.sshKeyEncoding = sshKeyEncoding;
            return this;
        }

        /**
         * @param sshKeyEncoding Specifies the public key encoding format to use in the response. To retrieve the public key in ssh-rsa format, use SSH. To retrieve the public key in PEM format, use PEM.
         * 
         * @return builder
         * 
         */
        public Builder sshKeyEncoding(String sshKeyEncoding) {
            return sshKeyEncoding(Output.of(sshKeyEncoding));
        }

        /**
         * @param sshPublicKey The SSH public key. The public key must be encoded in ssh-rsa format or PEM format.
         * 
         * @return builder
         * 
         */
        public Builder sshPublicKey(@Nullable Output<String> sshPublicKey) {
            $.sshPublicKey = sshPublicKey;
            return this;
        }

        /**
         * @param sshPublicKey The SSH public key. The public key must be encoded in ssh-rsa format or PEM format.
         * 
         * @return builder
         * 
         */
        public Builder sshPublicKey(String sshPublicKey) {
            return sshPublicKey(Output.of(sshPublicKey));
        }

        /**
         * @param tags A map of tags to add.
         * 
         * @return builder
         * 
         */
        public Builder tags(@Nullable Output<Map<String,String>> tags) {
            $.tags = tags;
            return this;
        }

        /**
         * @param tags A map of tags to add.
         * 
         * @return builder
         * 
         */
        public Builder tags(Map<String,String> tags) {
            return tags(Output.of(tags));
        }

        /**
         * @param uploadIamUserSshKey Whether to upload a public ssh key to the IAM user.
         * 
         * @return builder
         * 
         */
        public Builder uploadIamUserSshKey(@Nullable Output<Boolean> uploadIamUserSshKey) {
            $.uploadIamUserSshKey = uploadIamUserSshKey;
            return this;
        }

        /**
         * @param uploadIamUserSshKey Whether to upload a public ssh key to the IAM user.
         * 
         * @return builder
         * 
         */
        public Builder uploadIamUserSshKey(Boolean uploadIamUserSshKey) {
            return uploadIamUserSshKey(Output.of(uploadIamUserSshKey));
        }

        public UserArgs build() {
            $.name = Objects.requireNonNull($.name, "expected parameter 'name' to be non-null");
            $.path = Codegen.stringProp("path").output().arg($.path).def("/").getNullable();
            $.sshKeyEncoding = Codegen.stringProp("sshKeyEncoding").output().arg($.sshKeyEncoding).def("SSH").getNullable();
            return $;
        }
    }

}
