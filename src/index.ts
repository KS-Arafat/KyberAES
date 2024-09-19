import { log } from "node:console";
import { Recipient_instance, Sender_instance } from "./utils/Kyber_AES";

(async () => {
	const recipient = new Recipient_instance();
	const sender = new Sender_instance();

	await recipient.init();

	await sender.init(recipient.sharePublicRing());
	await recipient.set_CT(sender.share_CT());

	const encrypted_1 = sender.send_msg("Sender: Ola Ur Code is 💩");
	if (encrypted_1) log(recipient.receive_msg(encrypted_1));

	const encrypted_2 = recipient.send_msg("Recipient: Yo, Who tf r u 🤬");
	if (encrypted_2) log(sender.receive_msg(encrypted_2));

	/*
	 *
	 */
})();

function areUint8ArraysEqual(arr1: Uint8Array, arr2: Uint8Array): boolean {
	if (arr1.byteLength !== arr2.byteLength) return false;

	return arr1.every((value, index) => value === arr2[index]);
}
