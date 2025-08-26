function sendEmail() {
    const receiverEmail = document.getElementById("receiverEmail").value;
    const senderName = document.getElementById("senderName").value;
    const encryptedMessage = document.getElementById("outputText").value; // Encrypted msg

    if (!receiverEmail || !senderName || !encryptedMessage) {
        alert("Please fill all fields before sending email!");
        return;
    }

    fetch("/send_email", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            receiver_email: receiverEmail,
            sender_name: senderName,
            encrypted_message: encryptedMessage,
        }),
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === "success") {
            alert("✅ Email sent successfully!");
        } else {
            alert("❌ Failed to send: " + data.message);
        }
    })
    .catch(err => console.error(err));
}
