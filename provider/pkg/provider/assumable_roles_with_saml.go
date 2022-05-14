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
	"github.com/zchase/pulumi-aws-iam/pkg/utils"
)

const AssumableRolesWithSAMLIdentifier = "aws-iam:index:AssumableRolesWithSAML"

type AssumableRolesWithSAMLArgs struct {
	// List of SAML Provider IDs.
	ProviderIDs []string `pulumi:"providerIds"`

	// AWS SAML Endpoint.
	AWSSAMLEndpoint string `pulumi:"awsSamlEndpoint"`

	// Maximum CLI/API session duration in seconds between 3600 and 43200.
	MaxSessionDuration int `pulumi:"maxSessionDuration"`

	// Whether policies should be detached from this role when destroying.
	ForceDetachPolicies bool `pulumi:"forceDetachPolicies"`

	// IAM role with admin access.
	Admin utils.RoleArgs `pulumi:"admin"`

	// IAM role with poweruser access.
	Poweruser utils.RoleArgs `pulumi:"poweruser"`

	// IAM role with readonly access.
	Readonly utils.RoleArgs `pulumi:"readonly"`
}

type AssumableRolesWithSAML struct {
	pulumi.ResourceState

	// Admin role.
	Admin AssumableRoleOutput `pulumi:"admin"`

	// Poweruser role.
	Poweruser AssumableRoleOutput `pulumi:"poweruser"`

	// Readonly role.
	Readonly AssumableRoleOutput `pulumi:"readonly"`
}

func NewAssumableRolesWithSAML(ctx *pulumi.Context, name string, args *AssumableRolesWithSAMLArgs, opts ...pulumi.ResourceOption) (*AssumableRolesWithSAML, error) {
	if args == nil {
		args = &AssumableRolesWithSAMLArgs{}
	}

	component := &AssumableRolesWithSAML{}
	err := ctx.RegisterComponentResource(AssumableRolesWithSAMLIdentifier, name, component, opts...)
	if err != nil {
		return nil, err
	}

	opts = append(opts, pulumi.Parent(component))

	assumableRoleWithSAMLArgs := newIAMPolicyDocumentStatementConstructor("Allow", []string{"sts:AssumeRoleWithSAML"}).
		AddFederatedPrincipal(args.ProviderIDs).
		AddCondition("StringEquals", "SAML:aud", []string{args.AWSSAMLEndpoint}).
		Build()

	assumeRoleWithSAML, err := iam.GetPolicyDocument(ctx, assumableRoleWithSAMLArgs)
	if err != nil {
		return nil, err
	}

	roleOutput, err := utils.NewAssumableRoles(ctx, name, &utils.IAMAssumableRolesArgs{
		MaxSessionDuration:  args.MaxSessionDuration,
		ForceDetachPolicies: args.ForceDetachPolicies,
		AssumeRolePolicy:    assumeRoleWithSAML.Json,
		Admin:               args.Admin,
		Poweruser:           args.Poweruser,
		Readonly:            args.Readonly,
	}, opts...)
	if err != nil {
		return nil, err
	}

	component.Admin = createAssumableRoleOutput(roleOutput[utils.AdminRoleType], false)
	component.Poweruser = createAssumableRoleOutput(roleOutput[utils.PoweruserRoleType], false)
	component.Readonly = createAssumableRoleOutput(roleOutput[utils.PoweruserRoleType], false)

	return component, nil
}
