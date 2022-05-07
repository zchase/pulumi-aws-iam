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

const AssumableRolesIdentifier = "aws-iam:index:AssumableRoles"

type AssumableRolesRoleArgs struct {
	// IAM role name.
	Name string `pulumi:"name"`

	// Path of IAM role.
	Path string `pulumi:"path"`

	// List of policy ARNs to use.
	PolicyARNS []string `pulumi:"policyArns"`

	// Permissions boundary ARN to use.
	PermissionsBoundaryARN string `pulumi:"permissionsBoundaryArn"`

	// Whether admin role requires MFA.
	RequiresMFA bool `pulumi:"requiresMfa"`

	// A map of tags to add.
	Tags map[string]string `pulumi:"tags"`
}

type AssumableRolesArgs struct {
	// ARNs of AWS entities who can assume these roles.
	TrustedRoleArns []string `pulumi:"trustedRoleArns"`

	// AWS Services that can assume these roles.
	TrustedRoleServices []string `pulumi:"trustedRoleServices"`

	// Max age of valid MFA (in seconds) for roles which require MFA.
	MFAAge int `pulumi:"mfaAge"`

	// Maximum CLI/API session duration in seconds between 3600 and 43200.
	MaxSessionDuration int `pulumi:"maxSessionDuration"`

	// Whether policies should be detached from this role when destroying.
	ForceDetachPolicies bool `pulumi:"forceDetachPolicies"`

	// IAM role with admin access.
	Admin AssumableRolesRoleArgs `pulumi:"admin"`

	// IAM role with poweruser access.
	Poweruser AssumableRolesRoleArgs `pulumi:"poweruser"`

	// IAM role with readonly access.
	Readonly AssumableRolesRoleArgs `pulumi:"readonly"`
}

type AssumableRoleOutput struct {
	// ARN of the IAM role.
	RoleARN pulumi.StringOutput `pulumi:"roleArn"`

	// Name of the IAM role.
	RoleName pulumi.StringOutput `pulumi:"roleName"`

	// Path of the IAM role.
	RolePath pulumi.StringPtrOutput `pulumi:"rolePath"`

	// Unique ID of IAM role.
	RoleUniqueID pulumi.StringOutput `pulumi:"roleUniqueId"`

	// Whether readonly IAM role requires MFA.
	RequiresMFA bool `pulumi:"requiresMfa"`
}

type AssumableRoles struct {
	pulumi.ResourceState

	// Admin role.
	Admin AssumableRoleOutput `pulumi:"admin"`

	// Poweruser role.
	Poweruser AssumableRoleOutput `pulumi:"poweruser"`

	// Readonly role.
	Readonly AssumableRoleOutput `pulumi:"readonly"`
}

func NewAssumableRoles(ctx *pulumi.Context, name string, args *AssumableRolesArgs, opts ...pulumi.ResourceOption) (*AssumableRoles, error) {
	if args == nil {
		args = &AssumableRolesArgs{}
	}

	component := &AssumableRoles{}
	err := ctx.RegisterComponentResource(AssumableRoleIdentifier, name, component, opts...)
	if err != nil {
		return nil, err
	}

	opts = append(opts, pulumi.Parent(component))

	assumeRoleArgs := newIAMPolicyDocumentStatementConstructor("Allow", []string{"sts:AssumeRole"}).
		AddAWSPrincipal(args.TrustedRoleArns).
		AddServicePrincipal(args.TrustedRoleServices)

	assumeRoleWithMFAArgs := newIAMPolicyDocumentStatementConstructor("Allow", []string{"sts:AssumeRole"}).
		AddAWSPrincipal(args.TrustedRoleArns).
		AddServicePrincipal(args.TrustedRoleServices).
		AddCondition("Bool", "aws:MultiFactorAuthPresent", []string{"true"}).
		AddCondition("NumericLessThan", "aws:MultiFactorAuthAge", []string{fmt.Sprintf("%v", args.MFAAge)})

	assumeRole, err := iam.GetPolicyDocument(ctx, assumeRoleArgs.Build())
	if err != nil {
		return nil, err
	}

	assumeRoleMFA, err := iam.GetPolicyDocument(ctx, assumeRoleWithMFAArgs.Build())
	if err != nil {
		return nil, err
	}

	rolesToCreate := map[string]AssumableRolesRoleArgs{
		"admin":     args.Admin,
		"poweruser": args.Poweruser,
		"readonly":  args.Readonly,
	}

	roleOutput := make(map[string]*iam.Role)
	for typ, roleArgs := range rolesToCreate {
		rolePolicy := assumeRole.Json
		if roleArgs.RequiresMFA {
			rolePolicy = assumeRoleMFA.Json
		}

		if len(roleArgs.PolicyARNS) == 0 {
			switch typ {
			case "admin":
				roleArgs.PolicyARNS = append(roleArgs.PolicyARNS, "arn:aws:iam::aws:policy/AdministratorAccess")
			case "poweruser":
				roleArgs.PolicyARNS = append(roleArgs.PolicyARNS, "arn:aws:iam::aws:policy/PowerUserAccess")
			case "readonly":
				roleArgs.PolicyARNS = append(roleArgs.PolicyARNS, "arn:aws:iam::aws:policy/ReadOnlyAccess")
			}
		}

		role, err := createRoleWithAttachments(ctx, name, typ, roleArgs.PolicyARNS, &iam.RoleArgs{
			Name:                pulumi.String(roleArgs.Name),
			Path:                pulumi.String(roleArgs.Path),
			PermissionsBoundary: pulumi.String(roleArgs.PermissionsBoundaryARN),
			MaxSessionDuration:  pulumi.IntPtr(args.MaxSessionDuration),
			ForceDetachPolicies: pulumi.BoolPtr(args.ForceDetachPolicies),
			AssumeRolePolicy:    pulumi.String(rolePolicy),
			Tags:                pulumi.ToStringMap(roleArgs.Tags),
		}, opts...)
		if err != nil {
			return nil, err
		}

		roleOutput[typ] = role
	}

	component.Admin = createAssumableRoleOutput(roleOutput["admin"], args.Admin.RequiresMFA)
	component.Poweruser = createAssumableRoleOutput(roleOutput["poweruser"], args.Poweruser.RequiresMFA)
	component.Readonly = createAssumableRoleOutput(roleOutput["readonly"], args.Readonly.RequiresMFA)

	return component, nil
}
