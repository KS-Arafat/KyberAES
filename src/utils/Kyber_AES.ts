import { MlKem1024 } from "mlkem";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

class AES_engine {
	protected get_skR = () => new Uint8Array(randomBytes(32));

	public send_msg = (plaintext: string) => {
		try {
			if (!plaintext) throw new Error("No plaintext provided");
			const iv = randomBytes(16);
			const cipher = createCipheriv(
				"aes-256-gcm",
				this.get_skR(),
				new Uint8Array(iv)
			);

			let encrypted = cipher.update(plaintext, "utf-8", "hex");
			encrypted += cipher.final("hex");
			const tag = cipher.getAuthTag();
			// Encrypted:TAG:IV
			encrypted = `${encrypted}:${tag.toString("hex")}:${iv.toString("hex")}`;

			return encrypted;
		} catch (e) {
			console.log(e);
		}
	};

	public receive_msg = (mixedHex: string) => {
		try {
			const splited = mixedHex.split(":");

			const encrypted = splited[0];
			const tag_h = splited[1];
			const iv_h = splited[2];

			if (!(iv_h && tag_h && encrypted)) throw new Error("Error in Splitting");

			const iv_b = Buffer.from(iv_h, "hex");
			const tag_b = Buffer.from(tag_h, "hex");

			const decipher = createDecipheriv(
				"aes-256-gcm",
				this.get_skR(),
				new Uint8Array(iv_b)
			);

			let decrypted = "";
			decipher.setAuthTag(
				new Uint8Array(tag_b.buffer, tag_b.byteOffset, tag_b.length)
			);
			decrypted += decipher.update(encrypted, "hex", "utf-8");
			decrypted += decipher.final("utf-8");

			return decrypted;
		} catch (err) {
			console.error("Decryption error: ", err);
		}
	};
}

class Recipient_instance extends AES_engine {
	private CK_engine = new MlKem1024();

	private myPkR!: Uint8Array;
	private mySkR!: Uint8Array;
	private ssR!: Uint8Array;

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

	protected get_skR = () => new Uint8Array(Buffer.from(this.ssR));
}

class Sender_instance extends AES_engine {
	private CK_engine = new MlKem1024();

	private CT!: Uint8Array;
	private ssS!: Uint8Array;

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

	protected get_skR = () => new Uint8Array(Buffer.from(this.ssS));
}

export { Recipient_instance, Sender_instance };
