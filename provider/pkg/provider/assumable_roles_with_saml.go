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

const AssumableRolesWithSAMLIdentifier = "aws-iam:index:AssumableRolesWithSAML"

type AssumableRoleWithSAMLRoleArgs struct {
	// IAM role name.
	Name string `pulumi:"name"`

	// Path of IAM role.
	Path string `pulumi:"path"`

	// List of policy ARNs to use.
	PolicyARNS []string `pulumi:"policyArns"`

	// Permissions boundary ARN to use.
	PermissionsBoundaryARN string `pulumi:"permissionsBoundaryArn"`

	// A map of tags to add.
	Tags map[string]string `pulumi:"tags"`
}

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
	Admin AssumableRoleWithSAMLRoleArgs `pulumi:"admin"`

	// IAM role with poweruser access.
	Poweruser AssumableRoleWithSAMLRoleArgs `pulumi:"poweruser"`

	// IAM role with readonly access.
	Readonly AssumableRoleWithSAMLRoleArgs `pulumi:"readonly"`
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

	rolesToCreate := map[string]AssumableRoleWithSAMLRoleArgs{
		"admin":     args.Admin,
		"poweruser": args.Poweruser,
		"readonly":  args.Readonly,
	}

	roleOutput := make(map[string]*iam.Role)
	for typ, roleArgs := range rolesToCreate {
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
			AssumeRolePolicy:    pulumi.String(assumeRoleWithSAML.Json),
			Tags:                pulumi.ToStringMap(roleArgs.Tags),
		}, opts...)
		if err != nil {
			return nil, err
		}

		roleOutput[typ] = role
	}

	component.Admin = createAssumableRoleOutput(roleOutput["admin"], false)
	component.Poweruser = createAssumableRoleOutput(roleOutput["poweruser"], false)
	component.Readonly = createAssumableRoleOutput(roleOutput["readonly"], false)

	return component, nil
}
