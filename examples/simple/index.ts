import * as iam from "@pulumi/aws-iam";

// Account
// export const account = new iam.Account("account", {
//     accountAlias: "cool-alias",
//     minimumPasswordLength: 37,
//     requireNumbers: false,
// });

// Assumable Role
export const assumableRole = new iam.AssumableRole("assumable-role", {
    trustedRoleArns: [ "arn:aws:iam::307990089504:root", "arn:aws:iam::835367859851:user/pulumipus" ],
    customRolePolicyArns: [ "arn:aws:iam::aws:policy/AmazonCognitoReadOnly","arn:aws:iam::aws:policy/AlexaForBusinessFullAccess" ],
    role: {
        name: "custom",
        requiresMfa: true,
    },
});

// Assumable Role With OIDC
// export const assumableRoleWithOidc = new iam.AssumableRoleWithOIDC("assumable-role-with-oidc", {
//     role: {
//         name: "oidc-role",
//         policyArns: [ "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy" ],
//     },
//     tags: {
//         Role: "oidc-role",
//     },
//     providerUrls: ["oidc.eks.eu-west-1.amazonaws.com/id/BA9E170D464AF7B92084EF72A69B9DC8"],
// });

// Assumable Role With SAML
// export const assumableRoleWithSaml = new iam.AssumableRoleWithSAML("assumable-role-with-saml", {
//     role: {
//         name: "saml-role",
//         policyArns: [ "arn:aws:iam::aws:policy/ReadOnlyAccess" ],
//     },
//     tags: {
//         Role: "saml-role",
//     },
//     providerIds: [ "arn:aws:iam::235367859851:saml-provider/idp_saml" ],
// });

// Assumable Roles
// export const assumableRoles = new iam.AssumableRoles("assumable-roles", {
//     trustedRoleArns: [ "arn:aws:iam::307990089504:root", "arn:aws:iam::835367859851:user/anton" ],
//     admin: {},
//     poweruser: {
//         name: "developer",
//     },
//     readonly: {
//         requiresMfa: true,
//     },
// });

// Assumable Roles With SAML
// export const assumableRolesWithSaml = new iam.AssumableRolesWithSAML("assumable-role-with-saml", {
//     providerIds: [ "arn:aws:iam::235367859851:saml-provider/idp_saml" ],
//     admin: {},
//     poweruser: {
//         name: "developer",
//     },
//     readonly: {},
// });

// EKS Role
// export const eksRole = new iam.EKSRole("eks-role", {
//     role: {
//         name: "eks-role",
//         policyArns: [ "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy" ],
//     },
//     clusterServiceAccounts: {
//         "cluster1": [ "default:my-app" ],
//         "cluster2": [ "default:my-app", "canary:my-app" ],
//     },
//     tags: {
//         Name: "eks-role",
//     },
// });

// Group With Assumable Roles Policy
// export const groupWithAssumableRolesPolicy = new iam.GroupWithAssumableRolesPolicy("group-with-assumable-roles-policy", {
//     name: "production-readonly",
//     assumableRoles: [ "arn:aws:iam::835367859855:role/readonly" ],
//     groupUsers: [ "user1", "user2" ],
// });

// Group With Policies
// export const groupWithPolicies = new iam.GroupWithPolicies("group-with-policies", {
//     name: "superadmins",
//     groupUsers: [ "user1", "user2" ],
//     attachIamSelfManagementPolicy: true,
//     customGroupPolicyArns: [ "arn:aws:iam::aws:policy/AdministratorAccess" ],
//     customGroupPolicies: [{
//         "name": "AllowS3Listing",
//         "policy": "{}",
//     }],
// });

// Policy
// export const policy = new iam.Policy("policy", {
//     name: "example",
//     path: "/",
//     description: "My example policy",
//     tags: { "test": "tag" },
//     policyDocument: `{
//         "Version": "2012-10-17",
//         "Statement": [
//           {
//             "Action": [
//               "ec2:Describe*"
//             ],
//             "Effect": "Allow",
//             "Resource": "*"
//           }
//         ]
//     }`,
// });

// Read Only Policy
// export const readOnlyPolicy = new iam.ReadOnlyPolicy("read-only-policy", {
//     name: "example",
//     path: "/",
//     description: "My example read only policy",
//     allowedServices: [ "rds", "dynamo", "health" ],
// });

// Role For Service Accounts EKS
// export const roleForServiceAccountsEks = new iam.RoleForServiceAccountsEks("role-for-service-accounts-eks", {
//     role: {
//         name: "vpc-cni"
//     },
//     tags: {
//         Name: "vpc-cni-irsa",
//     },
//     oidcProviders: {
//         main: {
//             providerArn: "arn:aws:iam::012345678901:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/5C54DDF35ER19312844C7333374CC09D",
//             namespaceServiceAccounts: ["default:my-app", "canary:my-app"],
//         }
//     },
//     policies: {
//         vpnCni: {
//             attach: true,
//             enableIpv4: true,
//         },
//     },
// });

// User
// export const user = new iam.User("user", {
//     name: "pulumipus",
//     forceDestroy: true,
//     pgpKey: "keybase:test",
//     passwordResetRequired: false,
// });
