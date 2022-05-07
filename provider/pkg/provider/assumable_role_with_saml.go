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
)

const AssumableRoleWithSAMLIdentifier = "aws-iam:index:AssumableRoleWithSAML"

type AssumableRoleWithSAMLArgs struct {
	// List of SAML Provider IDs.
	ProviderIDs []string `pulumi:"providerIds"`

	// AWS SAML Endpoint.
	AWSSAMLEndpoint string `pulumi:"awsSamlEndpoint"`

	// A map of tags to add.
	Tags map[string]string `pulumi:"tags"`

	// IAM role.
	Role RoleArgs `pulumi:"role"`

	// Maximum CLI/API session duration in seconds between 3600 and 43200.
	MaxSessionDuration int `pulumi:"maxSessionDuration"`

	// Whether policies should be detached from this role when destroying.
	ForceDetachPolicies bool `pulumi:"forceDetachPolicies"`
}

type AssumableRoleWithSAML struct {
	pulumi.ResourceState

	// ARN of IAM role.
	Arn pulumi.StringOutput `pulumi:"arn"`

	// Name of IAM role.
	Name pulumi.StringOutput `pulumi:"name"`

	// Path of IAM role.
	Path pulumi.StringPtrOutput `pulumi:"path"`

	// Unique ID of IAM role.
	UniqueID pulumi.StringOutput `pulumi:"uniqueId"`
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

	policyDocArgs := newIAMPolicyDocumentStatementConstructor("Allow", []string{"sts:AssumeRoleWithSAML"}).
		AddFederatedPrincipal(args.ProviderIDs).
		AddCondition("StringEquals", "SAML:aud", []string{args.AWSSAMLEndpoint}).
		Build()

	policyDoc, err := iam.GetPolicyDocument(ctx, policyDocArgs)
	if err != nil {
		return nil, err
	}

	var roleNamePrefix pulumi.StringPtrInput
	roleName := pulumi.StringPtr(args.Role.Name)
	if args.Role.NamePrefix != "" {
		roleNamePrefix = pulumi.StringPtr(args.Role.NamePrefix)
		roleName = nil
	}

	role, err := iam.NewRole(ctx, name, &iam.RoleArgs{
		Name:                roleName,
		NamePrefix:          roleNamePrefix,
		Description:         pulumi.String(args.Role.Description),
		Path:                pulumi.String(args.Role.Path),
		MaxSessionDuration:  pulumi.IntPtr(args.MaxSessionDuration),
		ForceDetachPolicies: pulumi.BoolPtr(args.ForceDetachPolicies),
		PermissionsBoundary: pulumi.StringPtr(args.Role.PermissionsBoundaryArn),
		Tags:                pulumi.ToStringMap(args.Tags),
		AssumeRolePolicy:    pulumi.String(policyDoc.Json),
	}, opts...)
	if err != nil {
		return nil, err
	}

	for _, policyArn := range args.Role.PolicyArns {
		err = createRolePolicyAttachment(ctx, name, policyArn, role.Name, opts...)
		if err != nil {
			return nil, err
		}
	}

	component.Arn = role.Arn
	component.Name = role.Name
	component.Path = role.Path
	component.UniqueID = role.UniqueId

	return component, nil
}
