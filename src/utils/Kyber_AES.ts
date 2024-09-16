import { MlKem1024 } from "mlkem";
import { createCipheriv, createDecipheriv } from "node:crypto";

class Recipient_instance {
	private CK_engine = new MlKem1024();

	private myPkR!: Uint8Array;
	private mySkR!: Uint8Array;
	public ssR!: Uint8Array;

	private Init = false;

	public init = async () => {
		if (!this.Init) {
			const [pkR, skR] = await this.CK_engine.generateKeyPair();
			this.myPkR = pkR;
			this.mySkR = skR;
			this.Init = true;
		}
	};

	private initCheck = () => {
		if (!this.Init) {
			throw new Error("Recipient_instance not initialized");
		}
	};
	public regenerate_rings = async () => {
		this.initCheck();
		const [pkR, skR] = await this.CK_engine.generateKeyPair();
		this.myPkR = pkR;
		this.mySkR = skR;
	};

	public sharePublicRing = () => {
		this.initCheck();
		return this.myPkR;
	};

	public set_CT = async (CT: Uint8Array) => {
		this.initCheck();
		this.ssR = await this.CK_engine.decap(CT, this.mySkR);
	};

	public checkIfEmpty = (loc: string) => {
		this.initCheck();
		console.log(
			`PKR: ${
				!this.myPkR || this.myPkR.length === 0 ? "Bad" : "Good"
			} \t${loc}`,
			`\nSKR: ${
				!this.mySkR || this.mySkR.length === 0 ? "Bad" : "Good"
			} \t${loc}`,
			`\nssR: ${!this.ssR || this.ssR.length === 0 ? "Bad" : "Good"}\t${loc}`
		);
	};
}

class Sender_instance {
	private CK_engine = new MlKem1024();

	private CT!: Uint8Array;
	public ssS!: Uint8Array;

	private Init = false;

	public init = async (PkR: Uint8Array) => {
		if (!this.Init) {
			const [ct, ssS] = await this.CK_engine.encap(PkR);
			this.CT = ct;
			this.ssS = ssS;
			this.Init = true;
		}
	};

	private initCheck = () => {
		if (!this.Init) {
			throw new Error("Recipient_instance not initialized");
		}
	};

	public share_CT = () => {
		this.initCheck();
		return this.CT;
	};
}

export { Recipient_instance, Sender_instance };
