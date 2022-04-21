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
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/iam"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"golang.org/x/exp/slices"
)

const AssumableRoleWithSAMLIdentifier = "aws-iam:index:AssumableRoleWithSAML"

type AssumableRoleWithSAMLArgs struct {
	// ID of the SAML Provider. Use provider_ids to specify several IDs.
	ProviderID string `pulumi:"providerId"`

	// List of SAML Provider IDs.
	ProviderIDs []string `pulumi:"providerIds"`

	// AWS SAML Endpoint.
	AWSSAMLEndpoint string `pulumi:"awsSamlEndpoint"`

	// A map of tags to add.
	Tags map[string]string `pulumi:"tags"`

	// IAM role name.
	RoleName string `pulumi:"roleName"`

	// IAM role name prefix.
	RoleNamePrefix string `pulumi:"roleNamePrefix"`

	// IAM Role description.
	RoleDescription string `pulumi:"roleDescription"`

	// Path of IAM role.
	RolePath string `pulumi:"rolePath"`

	// Permissions boundary ARN to use for IAM role.
	RolePermissionsBoundaryArn string `pulumi:"rolePermissionsBoundaryArn"`

	// Maximum CLI/API session duration in seconds between 3600 and 43200.
	MaxSessionDuration int `pulumi:"maxSessionDuration"`

	// List of ARNs of IAM policies to attach to IAM role.
	RolePolicyArns []string `pulumi:"rolePolicyArns"`

	// Number of IAM policies to attach to IAM role.
	NumberOfRolePolicyArns int `pulumi:"numberOfRolePolicyArns"`

	// Whether policies should be detached from this role when destroying.
	ForceDetachPolicies bool `pulumi:"forceDetachPolicies"`
}

type AssumableRoleWithSAML struct {
	pulumi.ResourceState

	// ARN of IAM role.
	IAMRoleArn pulumi.StringOutput `pulumi:"iamRoleArn"`

	// Name of IAM role.
	IAMRoleName pulumi.StringOutput `pulumi:"iamRoleName"`

	// Path of IAM role.
	IAMRolePath pulumi.StringOutput `pulumi:"iamRolePath"`

	// Unique ID of IAM role.
	IAMRoleUniqueID pulumi.StringOutput `pulumi:"iamRoleUniqueId"`
}

func NewAssumableRoleWithSAML(ctx *pulumi.Context, name string, args *AssumableRoleWithSAMLArgs, opts ...pulumi.ResourceOption) (*AssumableRoleWithSAML, error) {
	if args == nil {
		args = &AssumableRoleWithSAMLArgs{}
	}

	component := &AssumableRoleWithSAML{}
	err := ctx.RegisterComponentResource(AssumableRoleWithSAMLIdentifier, name, component, opts...)
	if err != nil {
		return nil, err
	}

	opts = append(opts, pulumi.Parent(component))

	if !slices.Contains(args.ProviderIDs, args.ProviderID) {
		args.ProviderIDs = append(args.ProviderIDs, args.ProviderID)
	}

	effect := "Allow"
	policyDoc, err := iam.GetPolicyDocument(ctx, &iam.GetPolicyDocumentArgs{
		Statements: []iam.GetPolicyDocumentStatement{
			{
				Effect:  &effect,
				Actions: []string{"sts:AssumeRoleWithSAML"},
				Principals: []iam.GetPolicyDocumentStatementPrincipal{
					{
						Type:        "Federated",
						Identifiers: args.ProviderIDs,
					},
				},
				Conditions: []iam.GetPolicyDocumentStatementCondition{
					{
						Test:     "StringEquals",
						Variable: "SAML:aud",
						Values:   []string{args.AWSSAMLEndpoint},
					},
				},
			},
		},
	})

	role, err := iam.NewRole(ctx, name, &iam.RoleArgs{
		Name:                pulumi.String(args.RoleName),
		NamePrefix:          pulumi.String(args.RoleNamePrefix),
		Description:         pulumi.String(args.RoleDescription),
		Path:                pulumi.String(args.RolePath),
		MaxSessionDuration:  pulumi.IntPtr(args.MaxSessionDuration),
		ForceDetachPolicies: pulumi.BoolPtr(args.ForceDetachPolicies),
		PermissionsBoundary: pulumi.StringPtr(args.RolePermissionsBoundaryArn),
		Tags:                pulumi.ToStringMap(args.Tags),
		AssumeRolePolicy:    pulumi.String(policyDoc.Json),
	}, opts...)
	if err != nil {
		return nil, err
	}

	for _, policyArn := range args.RolePolicyArns {
		err = createRolePolicyAttachment(ctx, name, policyArn, role.Name, opts...)
		if err != nil {
			return nil, err
		}
	}

	return component, nil
}
