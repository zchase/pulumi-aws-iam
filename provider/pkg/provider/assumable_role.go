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

	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/iam"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

const AssumableRoleIdentifier = "aws-iam:index:AssumableRoleWithSAML"

type AssumableRoleArgs struct {
	// Actions of STS.
	TrustedRoleActions []string `pulumi:"trustedRoleActions"`

	// ARNs of AWS entities who can assume these roles.
	TrustedRoleArns []string `pulumi:"trustedRoleArns"`

	// AWS Services that can assume these roles.
	TrustedRoleServices []string `pulumi:"trustedRoleServices"`

	// Max age of valid MFA (in seconds) for roles which require MFA.
	MFAAge int `pulumi:"mfaAge"`

	// Maximum CLI/API session duration in seconds between 3600 and 43200.
	MaxSessionDuration int `pulumi:"maxSessionDuration"`

	// Whether to create an instance profile.
	CreateInstanceProfile bool `pulumi:"createInstanceProfile"`

	// IAM role name.
	RoleName string `pulumi:"roleName"`

	// IAM Role description.
	RoleDescription string `pulumi:"roleDescription"`

	// Path of IAM role.
	RolePath string `pulumi:"rolePath"`

	// Whether role requires MFA.
	RoleRequiresMFA bool `pulumi:"roleRequiresMfa"`

	// Permissions boundary ARN to use for IAM role.
	RolePermissionsBoundaryArn string `pulumi:"rolePermissionsBoundaryArn"`

	// A map of tags to add.
	Tags map[string]string `pulumi:"tags"`

	// List of ARNs of IAM policies to attach to IAM role.
	CustomRolePolicyArns []string `pulumi:"customRolePolicyArns"`

	// A custom role trust policy.
	CustomRoleTrustPolicy string `pulumi:"customRoleTrustPolicy"`

	// Number of IAM policies to attach to IAM role.
	NumberOfCustomRolePolicyArns int `pulumi:"numberOfCustomRolePolicyArns"`

	// Policy ARN to use for admin role.
	AdminRolePolicyArn string `pulumi:"adminRolePolicyArn"`

	// Policy ARN to use for poweruser role.
	PoweruserRolePolicyArn string `pulumi:"poweruserRolePolicyArn"`

	// Policy ARN to use for readonly role.
	ReadonlyRolePolicyArn string `pulumi:"readonlyRolePolicyArn"`

	// Whether to attach an admin policy to a role.
	AttachAdminPolicy bool `pulumi:"attachAdminPolicy"`

	// Whether to attach a poweruser policy to a role.
	AttachPoweruserPolicy bool `pulumi:"attachPoweruserPolicy"`

	// Whether to attach a readonly policy to a role.
	AttachReadonlyPolicy bool `pulumi:"attachReadonlyPolicy"`

	// Whether policies should be detached from this role when destroying.
	ForceDetachPolicies bool `pulumi:"forceDetachPolicies"`

	// STS ExternalId condition values to use with a role (when MFA is not required).
	RoleSTSExternalID []string `pulumi:"roleStsExternalId"`
}

type AssumableRole struct {
	pulumi.ResourceState

	// ARN of IAM role.
	IAMRoleArn pulumi.StringOutput `pulumi:"iamRoleArn"`

	// Name of IAM role.
	IAMRoleName pulumi.StringOutput `pulumi:"iamRoleName"`

	// Path of IAM role.
	IAMRolePath pulumi.StringOutput `pulumi:"iamRolePath"`

	// Unique ID of IAM role.
	IAMRoleUniqueID pulumi.StringOutput `pulumi:"iamRoleUniqueId"`

	// Whether IAM role requires MFA.
	RoleRequiresMFA pulumi.BoolOutput `pulumi:"roleRequiresMfa"`

	// ARN of IAM instance profile.
	IAMInstanceProfileArn pulumi.StringOutput `pulumi:"iamInstanceProfileArn"`

	// Name of IAM instance profile.
	IAMInstanceProfileName pulumi.StringOutput `pulumi:"iamInstanceProfileName"`

	// IAM Instance profile's ID.
	IAMInstanceProfileID pulumi.StringOutput `pulumi:"iamInstanceProfileId"`

	// Path of IAM instance profile.
	IAMInstanceProfilePath pulumi.StringOutput `pulumi:"iamInstanceProfilePath"`

	// STS ExternalId condition value to use with a role.
	RoleSTSExternalID pulumi.StringOutput `pulumi:"roleSTSExternalId"`
}

func createRolePolicyAttachment(ctx *pulumi.Context, name, policyArn string, roleName pulumi.StringOutput, opts ...pulumi.ResourceOption) error {
	_, err := iam.NewRolePolicyAttachment(ctx, name, &iam.RolePolicyAttachmentArgs{
		Role:      roleName,
		PolicyArn: pulumi.String(policyArn),
	}, opts...)
	return err
}

func NewAssumableRole(ctx *pulumi.Context, name string, args *AssumableRoleArgs, opts ...pulumi.ResourceOption) (*AssumableRole, error) {
	if args == nil {
		args = &AssumableRoleArgs{}
	}

	component := &AssumableRole{}
	err := ctx.RegisterComponentResource(AssumableRoleIdentifier, name, component, opts...)
	if err != nil {
		return nil, err
	}

	opts = append(opts, pulumi.Parent(component))

	effect := "Allow"
	var stsExternalIdPolicy iam.GetPolicyDocumentStatementCondition
	if len(args.RoleSTSExternalID) > 0 {
		stsExternalIdPolicy = iam.GetPolicyDocumentStatementCondition{
			Test:     "StringEquals",
			Variable: "sts:ExternalId",
			Values:   args.RoleSTSExternalID,
		}
	}

	assumeRolePolicy, err := iam.GetPolicyDocument(ctx, &iam.GetPolicyDocumentArgs{
		Statements: []iam.GetPolicyDocumentStatement{
			{
				Effect:  &effect,
				Actions: args.TrustedRoleActions,
				Principals: []iam.GetPolicyDocumentStatementPrincipal{
					{
						Type:        "AWS",
						Identifiers: args.TrustedRoleArns,
					},
					{
						Type:        "Service",
						Identifiers: args.TrustedRoleServices,
					},
				},
				Conditions: []iam.GetPolicyDocumentStatementCondition{
					stsExternalIdPolicy,
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	assumeRoleWithMFAPolicy, err := iam.GetPolicyDocument(ctx, &iam.GetPolicyDocumentArgs{
		Statements: []iam.GetPolicyDocumentStatement{
			{
				Effect:  &effect,
				Actions: args.TrustedRoleActions,
				Principals: []iam.GetPolicyDocumentStatementPrincipal{
					{
						Type:        "AWS",
						Identifiers: args.TrustedRoleArns,
					},
					{
						Type:        "Service",
						Identifiers: args.TrustedRoleServices,
					},
				},
				Conditions: []iam.GetPolicyDocumentStatementCondition{
					{
						Test:     "Bool",
						Variable: "aws:MultiFactorAuthPresent",
						Values:   []string{"true"},
					},
					{
						Test:     "NumericLessThan",
						Variable: "aws:MultiFactorAuthAge",
						Values: []string{
							fmt.Sprintf("%v", args.MFAAge),
						},
					},
					stsExternalIdPolicy,
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	rolePolicy := args.CustomRoleTrustPolicy
	if rolePolicy == "" {
		rolePolicy = assumeRoleWithMFAPolicy.Json

		if rolePolicy == "" {
			rolePolicy = assumeRolePolicy.Json
		}
	}

	role, err := iam.NewRole(ctx, name, &iam.RoleArgs{
		Name:                pulumi.String(args.RoleName),
		Path:                pulumi.String(args.RolePath),
		Description:         pulumi.String(args.RoleDescription),
		MaxSessionDuration:  pulumi.IntPtr(args.MaxSessionDuration),
		ForceDetachPolicies: pulumi.BoolPtr(args.ForceDetachPolicies),
		PermissionsBoundary: pulumi.StringPtr(args.RolePermissionsBoundaryArn),
		Tags:                pulumi.ToStringMap(args.Tags),
		AssumeRolePolicy:    pulumi.String(rolePolicy),
	}, opts...)
	if err != nil {
		return nil, err
	}

	for _, policyArn := range args.CustomRolePolicyArns {
		err = createRolePolicyAttachment(ctx, name, policyArn, role.Name, opts...)
		if err != nil {
			return nil, err
		}
	}

	if args.AttachAdminPolicy {
		err = createRolePolicyAttachment(ctx, name, args.AdminRolePolicyArn, role.Name, opts...)
		if err != nil {
			return nil, err
		}
	}

	if args.AttachPoweruserPolicy {
		err = createRolePolicyAttachment(ctx, name, args.PoweruserRolePolicyArn, role.Name, opts...)
		if err != nil {
			return nil, err
		}
	}

	if args.AttachReadonlyPolicy {
		err = createRolePolicyAttachment(ctx, name, args.ReadonlyRolePolicyArn, role.Name, opts...)
		if err != nil {
			return nil, err
		}
	}

	_, err = iam.NewInstanceProfile(ctx, name, &iam.InstanceProfileArgs{
		Name: pulumi.String(args.RoleName),
		Path: pulumi.String(args.RolePath),
		Role: role.Name,
		Tags: pulumi.ToStringMap(args.Tags),
	}, opts...)
	if err != nil {
		return nil, err
	}

	return component, nil
}
