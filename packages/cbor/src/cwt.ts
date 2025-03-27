import { EncryptedCWT } from "./cwt/encrypt";
import { MACedCWT } from "./cwt/mac";
import { SignedCWT } from "./cwt/sign";

export const CWT = {
	EncryptedCWT,
	MACedCWT,
	SignedCWT,
} as const;
