import { log } from "node:console";
import { Recipient_instance, Sender_instance } from "./utils/Kyber_AES";

(async () => {
	const recipient = new Recipient_instance();
	await recipient.init();
	const pkr = recipient.sharePublicRing();

	const sender = new Sender_instance();
	await sender.init(pkr);
	const ct = sender.share_CT();

	await recipient.set_CT(ct);

	log(areUint8ArraysEqual(recipient.ssR, sender.ssS));
})();

function areUint8ArraysEqual(arr1: Uint8Array, arr2: Uint8Array): boolean {
	if (arr1.byteLength !== arr2.byteLength) return false;

	return arr1.every((value, index) => value === arr2[index]);
}
