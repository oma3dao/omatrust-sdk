export type Hex = `0x${string}`;

export type InterfaceFlags = {
  human: boolean;
  api: boolean;
  smartContract: boolean;
};

export type InterfaceType = "human" | "api" | "contract";

export type RegistryStatus = "Active" | "Deprecated" | "Replaced";

export type Version = {
  major: number;
  minor: number;
  patch: number;
};
