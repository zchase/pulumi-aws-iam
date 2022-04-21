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
	"strings"

	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/iam"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"golang.org/x/exp/slices"
)

const AssumableRoleWithOIDCIdentifier = "aws-iam:index:AssumableRoleWithOIDC"

type AssumableRoleWithOIDCArgs struct {
	// URL of the OIDC Provider. Use provider_urls to specify several URLs.
	ProviderURL string `pulumi:"providerUrl"`

	// List of URLs of the OIDC Providers.
	ProviderURLs []string `pulumi:"providerUrls"`

	// The AWS account ID where the OIDC provider lives, leave empty to use the account for the AWS provider.
	AWSAccountID string `pulumi:"awsAccountId"`

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

	// The fully qualified OIDC subjects to be added to the role policy.
	OIDCFullyQualifiedSubjects []string `pulumi:"oidcFullyQualifiedSubjects"`

	// The OIDC subject using wildcards to be added to the role policy.
	OIDCSubjectsWithWildcards []string `pulumi:"oidcSubjectsWithWildcards"`

	// The audience to be added to the role policy. Set to sts.amazonaws.com for cross-account assumable role. Leave empty otherwise.
	OIDCFullyQualifiedAudiences []string `pulumi:"oidcFullyQualifiedAudiences"`

	// Whether policies should be detached from this role when destroying.
	ForceDetachPolicies bool `pulumi:"forceDetachPolicies"`
}

type AssumableRoleWithOIDC struct {
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

func NewIAMAssumableRoleWithOIDC(ctx *pulumi.Context, name string, args *AssumableRoleWithOIDCArgs, opts ...pulumi.ResourceOption) (*AssumableRoleWithOIDC, error) {
	if args == nil {
		args = &AssumableRoleWithOIDCArgs{}
	}

	component := &AssumableRoleWithOIDC{}
	err := ctx.RegisterComponentResource(AssumableRoleWithOIDCIdentifier, name, component, opts...)
	if err != nil {
		return nil, err
	}

	opts = append(opts, pulumi.Parent(component))

	if args.AWSAccountID == "" {
		account, err := aws.GetCallerIdentity(ctx)
		if err != nil {
			return nil, err
		}
		args.AWSAccountID = account.AccountId
	}

	currentPartition, err := aws.GetPartition(ctx, nil, nil)
	if err != nil {
		return nil, err
	}

	if !slices.Contains(args.ProviderURLs, args.ProviderURL) {
		args.ProviderURLs = append(args.ProviderURLs, args.ProviderURL)
	}

	for index, url := range args.ProviderURLs {
		args.ProviderURLs[index] = strings.ReplaceAll(url, "https://", "")
	}

	if args.NumberOfRolePolicyArns == 0 {
		args.NumberOfRolePolicyArns = len(args.RolePolicyArns)
	}

	var policies []string
	for _, url := range args.ProviderURLs {
		effect := "Allow"
		principalIdentifier := fmt.Sprintf("arn:%s:iam::%s:oidc-provider/%s", currentPartition.Partition, args.AWSAccountID, url)

		policyDoc, err := iam.GetPolicyDocument(ctx, &iam.GetPolicyDocumentArgs{
			Statements: []iam.GetPolicyDocumentStatement{
				{
					Effect:  &effect,
					Actions: []string{"sts:AssumeRoleWithWebIdentity"},
					Principals: []iam.GetPolicyDocumentStatementPrincipal{
						{
							Type:        "Federated",
							Identifiers: []string{principalIdentifier},
						},
					},
					Conditions: []iam.GetPolicyDocumentStatementCondition{
						{
							Test:     "StringEquals",
							Variable: fmt.Sprintf("%s:sub", url),
							Values:   args.OIDCFullyQualifiedSubjects,
						},
						{
							Test:     "StringLike",
							Variable: fmt.Sprintf("%s:sub", url),
							Values:   args.OIDCSubjectsWithWildcards,
						},
						{
							Test:     "StringLike",
							Variable: fmt.Sprintf("%s:aud", url),
							Values:   args.OIDCFullyQualifiedAudiences,
						},
					},
				},
			},
		})
		if err != nil {
			return nil, err
		}

		policies = append(policies, policyDoc.Json)
	}

	role, err := iam.NewRole(ctx, name, &iam.RoleArgs{
		Name:                pulumi.String(args.RoleName),
		NamePrefix:          pulumi.String(args.RoleNamePrefix),
		Description:         pulumi.String(args.RoleDescription),
		Path:                pulumi.String(args.RolePath),
		MaxSessionDuration:  pulumi.IntPtr(args.MaxSessionDuration),
		ForceDetachPolicies: pulumi.BoolPtr(args.ForceDetachPolicies),
		PermissionsBoundary: pulumi.StringPtr(args.RolePermissionsBoundaryArn),
		Tags:                pulumi.ToStringMap(args.Tags),
		AssumeRolePolicy:    pulumi.String(strings.Join(policies, "")),
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