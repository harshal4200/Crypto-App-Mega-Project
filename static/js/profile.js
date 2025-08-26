// Caesar Cipher
function caesarCipher(str, key) {
  return str.replace(/[a-z]/gi, (char) => {
    const base = char >= "a" ? 97 : 65;
    return String.fromCharCode(((char.charCodeAt(0) - base + key) % 26) + base);
  });
}

// XOR Cipher
function xorCipher(str, key) {
  let result = "";
  for (let i = 0; i < str.length; i++) {
    result += String.fromCharCode(str.charCodeAt(i) ^ key);
  }
  return result;
}

// Static Substitution Cipher
function substitutionCipher(str) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const reversed = "ZYXWVUTSRQPONMLKJIHGFEDCBA";
  let result = "";
  for (let ch of str.toUpperCase()) {
    const idx = alphabet.indexOf(ch);
    result += idx !== -1 ? reversed[idx] : ch;
  }
  return result;
}

// Static Substitution Decipher
function substitutionDecipher(str) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const reversed = "ZYXWVUTSRQPONMLKJIHGFEDCBA";
  let result = "";
  for (let ch of str.toUpperCase()) {
    const idx = reversed.indexOf(ch);
    result += idx !== -1 ? alphabet[idx] : ch;
  }
  return result;
}

// Encrypt
document.getElementById("encryptBtn").addEventListener("click", () => {
  const plainText = document.getElementById("plain-text").value;
  const caesarKey = parseInt(document.getElementById("caesar-key").value);
  const xorKey = parseInt(document.getElementById("xor-key").value);

  if (!plainText || isNaN(caesarKey) || isNaN(xorKey)) {
    alert("Enter text + Caesar Key + XOR Key!");
    return;
  }

  const step1 = caesarCipher(plainText, caesarKey);
  const step2 = xorCipher(step1, xorKey);
  const encrypted = substitutionCipher(step2);

  document.getElementById("encrypted-output").value = encrypted;
});

// Decrypt
function decryptText() {
  const encryptedText = document.getElementById("encrypted-input").value;
  const caesarKey = parseInt(document.getElementById("decrypt-caesar-key").value);
  const xorKey = parseInt(document.getElementById("decrypt-xor-key").value);

  if (!encryptedText || isNaN(caesarKey) || isNaN(xorKey)) {
    alert("Enter encrypted text + Caesar Key + XOR Key!");
    return;
  }

  const step1 = substitutionDecipher(encryptedText);
  const step2 = xorCipher(step1, xorKey);
  const decrypted = caesarCipher(step2, (26 - (caesarKey % 26)));

  document.getElementById("decrypted-output").value = decrypted;
}

// Copy helper
function copyToClipboard(id) {
  const el = document.getElementById(id);
  el.select();
  el.setSelectionRange(0, 99999);
  document.execCommand("copy");
  alert("Copied!");
}

// Email send
document.getElementById("emailForm").addEventListener("submit", async function(e) {
    e.preventDefault();
    const toEmail = document.getElementById("toEmail").value;
    const subject = "Encrypted Message from Crypto App";
    const body = document.getElementById("encrypted-output").value;

    if(!body){
        alert("No message to send!");
        return;
    }

    try{
        const res = await fetch("/send_email", {
            method: "POST",
            headers: {"Content-Type":"application/json"},
            body: JSON.stringify({to_email: toEmail, subject: subject, body: body})
        });
        const data = await res.json();
        alert(data.message || data.error);
    }catch(err){
        alert("Failed to send email!");
        console.error(err);
    }
});