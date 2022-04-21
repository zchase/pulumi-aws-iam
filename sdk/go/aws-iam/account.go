// Code generated by Pulumi SDK Generator DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package awsiam

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type Account struct {
	pulumi.ResourceState

	// The AWS Account ID number of the account that owns or contains the calling entity
	CallerIdentityAccountId pulumi.StringOutput `pulumi:"callerIdentityAccountId"`
	// The AWS ARN associated with the calling entity
	CallerIdentityArn pulumi.StringOutput `pulumi:"callerIdentityArn"`
	// The unique identifier of the calling entity
	CallerIdentityUserId pulumi.StringOutput `pulumi:"callerIdentityUserId"`
	// Indicates whether passwords in the account expire. Returns true if max password age contains a value greater than 0. Returns false if it is 0 or not present.
	IamAccountPasswordPolicyExpirePasswords pulumi.BoolOutput `pulumi:"iamAccountPasswordPolicyExpirePasswords"`
}

// NewAccount registers a new resource with the given unique name, arguments, and options.
func NewAccount(ctx *pulumi.Context,
	name string, args *AccountArgs, opts ...pulumi.ResourceOption) (*Account, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.AccountAlias == nil {
		return nil, errors.New("invalid value for required argument 'AccountAlias'")
	}
	if isZero(args.AllowUsersToChangePassword) {
		args.AllowUsersToChangePassword = pulumi.BoolPtr(true)
	}
	if isZero(args.CreateAccountPasswordPolicy) {
		args.CreateAccountPasswordPolicy = pulumi.BoolPtr(true)
	}
	if isZero(args.GetCallerIdentity) {
		args.GetCallerIdentity = pulumi.BoolPtr(true)
	}
	if isZero(args.HardExpiry) {
		args.HardExpiry = pulumi.BoolPtr(false)
	}
	if isZero(args.MaxPasswordAge) {
		args.MaxPasswordAge = pulumi.IntPtr(0)
	}
	if isZero(args.MinimumPasswordLength) {
		args.MinimumPasswordLength = pulumi.IntPtr(8)
	}
	if isZero(args.RequireLowercaseCharacters) {
		args.RequireLowercaseCharacters = pulumi.BoolPtr(true)
	}
	if isZero(args.RequireNumbers) {
		args.RequireNumbers = pulumi.BoolPtr(true)
	}
	if isZero(args.RequireSymbols) {
		args.RequireSymbols = pulumi.BoolPtr(true)
	}
	if isZero(args.RequireUppercaseCharacters) {
		args.RequireUppercaseCharacters = pulumi.BoolPtr(true)
	}
	var resource Account
	err := ctx.RegisterRemoteComponentResource("aws-iam:index:Account", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

type accountArgs struct {
	// AWS IAM account alias for this account.
	AccountAlias string `pulumi:"accountAlias"`
	// Whether to allow users to change their own password.
	AllowUsersToChangePassword *bool `pulumi:"allowUsersToChangePassword"`
	// Whether to create AWS IAM account password policy.
	CreateAccountPasswordPolicy *bool `pulumi:"createAccountPasswordPolicy"`
	// Whether to get AWS account ID, User ID, and ARN in which Terraform is authorized.
	GetCallerIdentity *bool `pulumi:"getCallerIdentity"`
	// Whether users are prevented from setting a new password after their password has expired (i.e. require administrator reset).
	HardExpiry *bool `pulumi:"hardExpiry"`
	// The number of days that an user password is valid.
	MaxPasswordAge *int `pulumi:"maxPasswordAge"`
	// Minimum length to require for user passwords.
	MinimumPasswordLength *int `pulumi:"minimumPasswordLength"`
	// The number of previous passwords that users are prevented from reusing.
	PasswordReusePrevention *bool `pulumi:"passwordReusePrevention"`
	// Whether to require lowercase characters for user passwords.
	RequireLowercaseCharacters *bool `pulumi:"requireLowercaseCharacters"`
	// Whether to require numbers for user passwords.
	RequireNumbers *bool `pulumi:"requireNumbers"`
	// Whether to require symbols for user passwords.
	RequireSymbols *bool `pulumi:"requireSymbols"`
	// Whether to require uppercase characters for user passwords.
	RequireUppercaseCharacters *bool `pulumi:"requireUppercaseCharacters"`
}

// The set of arguments for constructing a Account resource.
type AccountArgs struct {
	// AWS IAM account alias for this account.
	AccountAlias pulumi.StringInput
	// Whether to allow users to change their own password.
	AllowUsersToChangePassword pulumi.BoolPtrInput
	// Whether to create AWS IAM account password policy.
	CreateAccountPasswordPolicy pulumi.BoolPtrInput
	// Whether to get AWS account ID, User ID, and ARN in which Terraform is authorized.
	GetCallerIdentity pulumi.BoolPtrInput
	// Whether users are prevented from setting a new password after their password has expired (i.e. require administrator reset).
	HardExpiry pulumi.BoolPtrInput
	// The number of days that an user password is valid.
	MaxPasswordAge pulumi.IntPtrInput
	// Minimum length to require for user passwords.
	MinimumPasswordLength pulumi.IntPtrInput
	// The number of previous passwords that users are prevented from reusing.
	PasswordReusePrevention pulumi.BoolPtrInput
	// Whether to require lowercase characters for user passwords.
	RequireLowercaseCharacters pulumi.BoolPtrInput
	// Whether to require numbers for user passwords.
	RequireNumbers pulumi.BoolPtrInput
	// Whether to require symbols for user passwords.
	RequireSymbols pulumi.BoolPtrInput
	// Whether to require uppercase characters for user passwords.
	RequireUppercaseCharacters pulumi.BoolPtrInput
}

func (AccountArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*accountArgs)(nil)).Elem()
}

type AccountInput interface {
	pulumi.Input

	ToAccountOutput() AccountOutput
	ToAccountOutputWithContext(ctx context.Context) AccountOutput
}

func (*Account) ElementType() reflect.Type {
	return reflect.TypeOf((**Account)(nil)).Elem()
}

func (i *Account) ToAccountOutput() AccountOutput {
	return i.ToAccountOutputWithContext(context.Background())
}

func (i *Account) ToAccountOutputWithContext(ctx context.Context) AccountOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AccountOutput)
}

// AccountArrayInput is an input type that accepts AccountArray and AccountArrayOutput values.
// You can construct a concrete instance of `AccountArrayInput` via:
//
//          AccountArray{ AccountArgs{...} }
type AccountArrayInput interface {
	pulumi.Input

	ToAccountArrayOutput() AccountArrayOutput
	ToAccountArrayOutputWithContext(context.Context) AccountArrayOutput
}

type AccountArray []AccountInput

func (AccountArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Account)(nil)).Elem()
}

func (i AccountArray) ToAccountArrayOutput() AccountArrayOutput {
	return i.ToAccountArrayOutputWithContext(context.Background())
}

func (i AccountArray) ToAccountArrayOutputWithContext(ctx context.Context) AccountArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AccountArrayOutput)
}

// AccountMapInput is an input type that accepts AccountMap and AccountMapOutput values.
// You can construct a concrete instance of `AccountMapInput` via:
//
//          AccountMap{ "key": AccountArgs{...} }
type AccountMapInput interface {
	pulumi.Input

	ToAccountMapOutput() AccountMapOutput
	ToAccountMapOutputWithContext(context.Context) AccountMapOutput
}

type AccountMap map[string]AccountInput

func (AccountMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Account)(nil)).Elem()
}

func (i AccountMap) ToAccountMapOutput() AccountMapOutput {
	return i.ToAccountMapOutputWithContext(context.Background())
}

func (i AccountMap) ToAccountMapOutputWithContext(ctx context.Context) AccountMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AccountMapOutput)
}

type AccountOutput struct{ *pulumi.OutputState }

func (AccountOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Account)(nil)).Elem()
}

func (o AccountOutput) ToAccountOutput() AccountOutput {
	return o
}

func (o AccountOutput) ToAccountOutputWithContext(ctx context.Context) AccountOutput {
	return o
}

type AccountArrayOutput struct{ *pulumi.OutputState }

func (AccountArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Account)(nil)).Elem()
}

func (o AccountArrayOutput) ToAccountArrayOutput() AccountArrayOutput {
	return o
}

func (o AccountArrayOutput) ToAccountArrayOutputWithContext(ctx context.Context) AccountArrayOutput {
	return o
}

func (o AccountArrayOutput) Index(i pulumi.IntInput) AccountOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Account {
		return vs[0].([]*Account)[vs[1].(int)]
	}).(AccountOutput)
}

type AccountMapOutput struct{ *pulumi.OutputState }

func (AccountMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Account)(nil)).Elem()
}

func (o AccountMapOutput) ToAccountMapOutput() AccountMapOutput {
	return o
}

func (o AccountMapOutput) ToAccountMapOutputWithContext(ctx context.Context) AccountMapOutput {
	return o
}

func (o AccountMapOutput) MapIndex(k pulumi.StringInput) AccountOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Account {
		return vs[0].(map[string]*Account)[vs[1].(string)]
	}).(AccountOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*AccountInput)(nil)).Elem(), &Account{})
	pulumi.RegisterInputType(reflect.TypeOf((*AccountArrayInput)(nil)).Elem(), AccountArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*AccountMapInput)(nil)).Elem(), AccountMap{})
	pulumi.RegisterOutputType(AccountOutput{})
	pulumi.RegisterOutputType(AccountArrayOutput{})
	pulumi.RegisterOutputType(AccountMapOutput{})
}