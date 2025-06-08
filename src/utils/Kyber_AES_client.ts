import { MlKem1024 } from "mlkem";

function bufferToHex(buffer: ArrayBuffer | Uint8Array): string {
	const byteArray =
		buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
	return Array.from(byteArray)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

function hexToBuffer(hex: string): Uint8Array {
	if (hex.startsWith("0x")) {
		hex = hex.slice(2);
	}

	if (hex.length % 2 !== 0) {
		throw new Error("Invalid hex string. Length must be even.");
	}

	const buffer = new Uint8Array(hex.length / 2);
	for (let i = 0; i < hex.length; i += 2) {
		buffer[i / 2] = parseInt(hex.slice(i, i + 2), 16);
	}
	return buffer;
}

class AES_engine {
	private ssD: Uint8Array = crypto.getRandomValues(new Uint8Array(32));

	protected get_skR = () => new Uint8Array(this.ssD);

	public send_msg = async (plaintext: string) => {
		try {
			if (!plaintext) throw new Error("No plaintext provided");
			const iv = crypto.getRandomValues(new Uint8Array(12));

			const key = await crypto.subtle.importKey(
				"raw",
				this.get_skR(),
				{ name: "AES-GCM" },
				false,
				["encrypt"]
			);

			const encoder = new TextEncoder();
			const encodedText = encoder.encode(plaintext);

			const ciphertextBuffer = await crypto.subtle.encrypt(
				{
					name: "AES-GCM",
					iv,
				},
				key,
				encodedText
			);

			const ciphertext = new Uint8Array(ciphertextBuffer);

			const encryptedHex = bufferToHex(ciphertext);
			const ivHex = bufferToHex(iv);
			const keyBytesHex = bufferToHex(this.get_skR());
			return `${encryptedHex}:${ivHex}:${keyBytesHex}`;
		} catch (e) {
			console.log(e);
		}
	};

	public receive_msg = async (encrypted: string) => {
		const [encryptedHex, ivHex, keyBytesHex] = encrypted.split(":");

		const ciphertext = hexToBuffer(encryptedHex) as Uint8Array<ArrayBuffer>;
		const iv = hexToBuffer(ivHex) as Uint8Array<ArrayBuffer>;
		const keyBytes = hexToBuffer(keyBytesHex);
		const key = await crypto.subtle.importKey(
			"raw",
			keyBytes as any,
			{ name: "AES-GCM" },
			false,
			["decrypt"]
		);

		const decryptedBuffer = await crypto.subtle.decrypt(
			{
				name: "AES-GCM",
				iv,
			},
			key,
			ciphertext
		);

		return new TextDecoder().decode(decryptedBuffer);
	};
}

class Recipient_client extends AES_engine {
	private CK_engine = new MlKem1024();

	private myPkR!: Uint8Array;
	private mySkR!: Uint8Array;
	private ssR!: Uint8Array;

	private Init = false;

	protected get_skR = () => new Uint8Array(this.ssR);
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

class Sender_client extends AES_engine {
	private CK_engine = new MlKem1024();

	private CT!: Uint8Array;
	private ssS!: Uint8Array;

	private Init = false;
	protected get_skR = () => new Uint8Array(this.ssS);
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

export {
	Recipient_client,
	Sender_client,
	AES_engine,
	bufferToHex,
	hexToBuffer,
};
