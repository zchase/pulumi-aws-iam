import * as iam from "@pulumi/aws-iam";

const account = new iam.IAMAccount("my-account", {
    accountAlias: "wow-cool-alias",
})

export const wowOutput = account.callerIdentityAccountId;
