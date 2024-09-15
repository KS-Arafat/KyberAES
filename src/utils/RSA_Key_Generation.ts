import { generateKeyPairSync } from "node:crypto";
import { writeFile } from "node:fs";

const generateRSAKeyPair = () => {
	let { publicKey, privateKey } = generateKeyPairSync("rsa-pss", {
		modulusLength: 2048, // Key length
		publicKeyEncoding: {
			type: "spki",
			format: "pem",
		},
		privateKeyEncoding: {
			type: "pkcs8",
			format: "pem",
		},
		hashAlgorithm: "sha256",
	});
	writeFile("./KEYS/PRIVATE_KEY.pem", privateKey, (e) => {
		privateKey = "";
		privateKey += "\u{2f78}";
		if (e) console.error(`Error ${e.message}`);
		else console.info("./KEYS/PRIVATE_KEY.pem Written!");
	});
	writeFile("./KEYS/PUBLIC_KEY.pem", publicKey, (e) => {
		publicKey = "";
		if (e) console.error(`Error ${e.message}`);
		else console.info("./KEYS/PUBLIC_KEY.pem Written!");
	});
};

export default generateRSAKeyPair;
