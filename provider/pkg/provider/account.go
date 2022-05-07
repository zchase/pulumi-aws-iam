// Copyright 2016-2022, Pulumi Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package provider

import (
	"fmt"

	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/iam"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

const AccountIdentifier = "aws-iam:index:Account"

type AccountArgs struct {
	// Whether to get AWS account ID, User ID, and ARN in which Terraform is authorized.
	GetCallerIdentity bool `pulumi:"getCallerIdentity"`

	// AWS IAM account alias for this account.
	AccountAlias string `pulumi:"accountAlias"`

	// The number of days that an user password is valid.
	MaxPasswordAge int `pulumi:"maxPasswordAge"`

	// Minimum length to require for user passwords.
	MinimumPasswordLength int `pulumi:"minimumPasswordLength"`

	// Whether to allow users to change their own password.
	AllowUsersToChangePassword bool `pulumi:"allowUsersToChangePassword"`

	// Whether users are prevented from setting a new password after their password has expired (i.e. require administrator reset).
	HardExpiry bool `pulumi:"hardExpiry"`

	// The number of previous passwords that users are prevented from reusing.
	PasswordReusePrevention int `pulumi:"passwordReusePrevention"`

	// Whether to require lowercase characters for user passwords.
	RequireLowercaseCharacters bool `pulumi:"requireLowercaseCharacters"`

	// Whether to require uppercase characters for user passwords.
	RequireUppercaseCharacters bool `pulumi:"requireUppercaseCharacters"`

	// Whether to require numbers for user passwords.
	RequireNumbers bool `pulumi:"requireNumbers"`

	// Whether to require symbols for user passwords.
	RequireSymbols bool `pulumi:"requireSymbols"`
}

type Account struct {
	pulumi.ResourceState

	// The AWS Account ID number of the account that owns or contains the calling entity.
	Id string `pulumi:"id"`

	// The AWS ARN associated with the calling entity.
	Arn string `pulumi:"arn"`

	// The unique identifier of the calling entity.
	UserId string `pulumi:"userId"`

	// Indicates whether passwords in the account expire. Returns true if max password age contains a value greater than 0. Returns false if it is 0 or not present.
	PasswordPolicyExpirePasswords pulumi.BoolOutput `pulumi:"passwordPolicyExpirePasswords"`
}

func NewIAMAccount(ctx *pulumi.Context, name string, args *AccountArgs, opts ...pulumi.ResourceOption) (*Account, error) {
	if args == nil {
		args = &AccountArgs{}
	}

	component := &Account{}
	err := ctx.RegisterComponentResource(AccountIdentifier, name, component, opts...)
	if err != nil {
		return nil, err
	}

	opts = append(opts, pulumi.Parent(component))

	account, err := aws.GetCallerIdentity(ctx)
	if err != nil {
		return nil, err
	}

	aliasName := fmt.Sprintf("%s-account-alias", name)
	_, err = iam.NewAccountAlias(ctx, aliasName, &iam.AccountAliasArgs{
		AccountAlias: pulumi.String(args.AccountAlias),
	}, opts...)
	if err != nil {
		return nil, err
	}

	passwordPolicyName := fmt.Sprintf("%s-password-policy", name)
	passwordPolicy, err := iam.NewAccountPasswordPolicy(ctx, passwordPolicyName, &iam.AccountPasswordPolicyArgs{
		MaxPasswordAge:             pulumi.Int(args.MaxPasswordAge),
		MinimumPasswordLength:      pulumi.Int(args.MinimumPasswordLength),
		AllowUsersToChangePassword: pulumi.Bool(args.AllowUsersToChangePassword),
		HardExpiry:                 pulumi.Bool(args.HardExpiry),
		PasswordReusePrevention:    pulumi.Int(args.PasswordReusePrevention),
		RequireLowercaseCharacters: pulumi.Bool(args.RequireLowercaseCharacters),
		RequireUppercaseCharacters: pulumi.Bool(args.RequireUppercaseCharacters),
		RequireNumbers:             pulumi.Bool(args.RequireNumbers),
		RequireSymbols:             pulumi.Bool(args.RequireSymbols),
	}, opts...)
	if err != nil {
		return nil, err
	}

	component.Id = account.AccountId
	component.Arn = account.Arn
	component.UserId = account.UserId
	component.PasswordPolicyExpirePasswords = passwordPolicy.ExpirePasswords

	return component, nil
}
