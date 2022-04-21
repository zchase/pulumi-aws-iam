// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "./utilities";

// Export members:
export * from "./account";
export * from "./assumableRoleWithOIDC";
export * from "./assumableRoleWithSAML";
export * from "./policy";
export * from "./provider";

// Export sub-modules:
import * as types from "./types";

export {
    types,
};

// Import resources to register:
import { Account } from "./account";
import { AssumableRoleWithOIDC } from "./assumableRoleWithOIDC";
import { AssumableRoleWithSAML } from "./assumableRoleWithSAML";
import { Policy } from "./policy";

const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "aws-iam:index:Account":
                return new Account(name, <any>undefined, { urn })
            case "aws-iam:index:AssumableRoleWithOIDC":
                return new AssumableRoleWithOIDC(name, <any>undefined, { urn })
            case "aws-iam:index:AssumableRoleWithSAML":
                return new AssumableRoleWithSAML(name, <any>undefined, { urn })
            case "aws-iam:index:Policy":
                return new Policy(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("aws-iam", "index", _module)

import { Provider } from "./provider";

pulumi.runtime.registerResourcePackage("aws-iam", {
    version: utilities.getVersion(),
    constructProvider: (name: string, type: string, urn: string): pulumi.ProviderResource => {
        if (type !== "pulumi:providers:aws-iam") {
            throw new Error(`unknown provider type ${type}`);
        }
        return new Provider(name, <any>undefined, { urn });
    },
});
