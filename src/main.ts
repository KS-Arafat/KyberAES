import {
	Recipient_client,
	Sender_client,
	bufferToHex,
	hexToBuffer,
} from "./utils/Kyber_AES_client";
import { Notyf } from "notyf";

// async () => {
// 	const r_user = new Recipient_client();
// 	const s_user = new Sender_client();

// 	await r_user.init();

// 	await s_user.init(r_user.sharePublicRing());
// 	await r_user.set_CT(s_user.share_CT());

// 	const encrypted_1 = await s_user.send_msg("user1: Ola Ur Code is 💩");
// 	if (encrypted_1) console.log(await r_user.receive_msg(encrypted_1));

// 	const encrypted_2 = await r_user.send_msg("user2: Yo, Who tf r u 🤬");
// 	if (encrypted_2) console.log(await s_user.receive_msg(encrypted_2));
// };

const notyf = new Notyf({
	position: {
		x: "right",
		y: "top",
	},
	dismissible: true,
	duration: 2500,
});

const btn_getkey = document.getElementById("getkeybtn") as HTMLButtonElement;
const textarea_getkey = document.getElementById(
	"getkey"
) as HTMLTextAreaElement;
textarea_getkey.value = "";

const btn_setkey = document.getElementById("setkeybtn") as HTMLButtonElement;
const textarea_setkey = document.getElementById(
	"setkey"
) as HTMLTextAreaElement;
textarea_setkey.value = "";

const btn_setCT = document.getElementById("setctbtn") as HTMLButtonElement;
const textarea_setCT = document.getElementById("setct") as HTMLTextAreaElement;
textarea_setCT.value = "";

const HideNode = (node: HTMLElement | null) => {
	if (node) {
		node.style.display = "none";
	}
};
const ShowNode = (node: HTMLElement | null) => {
	if (node) {
		node.style.display = "flex";
	}
};

const recipient = new Recipient_client();
const sender = new Sender_client();

const div_setCT = document.getElementById("div_setck");
const div_getCT = document.getElementById("div_genct");
const div_genkey = document.getElementById("div_genkey");

let userType: "recipient" | "sender" | null = null;

if (btn_getkey) {
	btn_getkey.addEventListener("click", async () => {
		await recipient.init();

		if (recipient.sharePublicRing().length <= 0) {
			notyf.error("Failed to generate key pair");
			return;
		}
		textarea_getkey.value = bufferToHex(recipient.sharePublicRing());
		await navigator.clipboard.writeText(textarea_getkey.value);
		ShowNode(div_setCT);
		HideNode(div_getCT);
		HideNode(div_genkey);
		notyf.success("Key Copied to clipboard");
	});
}

if (btn_setkey) {
	btn_setkey.addEventListener("click", async () => {
		try {
			await sender.init(new Uint8Array(hexToBuffer(textarea_setkey.value)));
			notyf.success("Key set successfully");
			const CT = bufferToHex(sender.share_CT());
			await navigator.clipboard.writeText(CT);
			textarea_setkey.value = CT;
			HideNode(div_genkey);
			HideNode(div_getCT);
			userType = "sender";
			notyf.success("CT Key Copied");
		} catch (error) {
			notyf.error("Failed to set key");
			console.error(error);
		}
	});
}

if (btn_setCT) {
	btn_setCT.addEventListener("click", async () => {
		try {
			await recipient.set_CT(new Uint8Array(hexToBuffer(textarea_setCT.value)));
			notyf.success("CT set successfully");
			HideNode(div_setCT);
			userType = "recipient";
			notyf.success("Client Synced");
		} catch (error) {
			notyf.error("Failed to set CT");
			console.error(error);
		}
	});
}

const pre_check = () => {
	if (userType === "recipient") return recipient;
	else if (userType === "sender") return sender;
	else {
		notyf.error("Please set your key first");
		return;
	}
};

const btn_send = document.getElementById("send") as HTMLButtonElement;
const btn_refresh = document.getElementById("refresh") as HTMLButtonElement;
const msgbox = document.getElementById("messages") as HTMLDivElement;
const input = document.getElementById("chat-input") as HTMLInputElement;

if (btn_send)
	btn_send.addEventListener("click", async () => {
		let cryptoEngine;
		if (!cryptoEngine) {
			cryptoEngine = pre_check();
			if (!cryptoEngine) return;
		}

		const inputValue = input.value.trim();
		const encrypted = await cryptoEngine.send_msg(inputValue);
		if (!encrypted) {
			notyf.error("Failed to send message");
			return;
		}
		await navigator.clipboard.writeText(encrypted);
		msgbox.insertAdjacentHTML(
			"beforeend",
			`<div class="flex flex-col items-end">
					<div class="rounded-lg bg-blue-500 px-4 py-2 text-sm text-white">
						${inputValue}
					</div>
				</div>`
		);
		input.value = "";
		notyf.success("Message sent");
	});

if (btn_refresh)
	btn_refresh.addEventListener("click", async () => {
		let cryptoEngine;
		if (!cryptoEngine) {
			cryptoEngine = pre_check();
			if (!cryptoEngine) return;
		}

		const encrypted = await navigator.clipboard.readText();

		const decrypted = await cryptoEngine.receive_msg(encrypted);
		if (!decrypted) {
			notyf.error("Failed to receive message");
			return;
		}
		msgbox.insertAdjacentHTML(
			"beforeend",
			`<div class="flex flex-col items-start">
					<div class="rounded-lg bg-gray-200 px-4 py-2 text-sm text-gray-800">
					${decrypted}
					</div>
				</div>`
		);
		notyf.success("Refreshed messages");
	});
