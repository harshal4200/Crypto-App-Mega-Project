document.addEventListener("DOMContentLoaded", function () {
  const chatWindow = document.getElementById("crypto-chat");
  const chatInput = document.getElementById("crypto-input");
  const sendBtn = document.getElementById("crypto-send");
  const themeToggle = document.getElementById("theme-toggle");
  const body = document.body;

  let darkMode = true; // default
  body.setAttribute("data-theme", "dark");

  // Theme toggle
  function toggleTheme() {
    darkMode = !darkMode;
    body.setAttribute("data-theme", darkMode ? "dark" : "light");
  }
  themeToggle?.addEventListener("click", toggleTheme);

  // Chat send
  async function sendMessage() {
    const message = chatInput.value.trim();
    if (!message) return;

    chatWindow.innerHTML += `<div class="d-flex justify-content-end mb-2">
      <div class="chat-bubble user">${message}</div>
    </div>`;
    chatInput.value = "";
    chatWindow.scrollTop = chatWindow.scrollHeight;

    const aiDiv = document.createElement("div");
    aiDiv.className = "d-flex justify-content-start mb-2";
    aiDiv.innerHTML = `<div class="chat-bubble bot"><span>🤖 Crypto Mentor is thinking...</span></div>`;
    chatWindow.appendChild(aiDiv);
    chatWindow.scrollTop = chatWindow.scrollHeight;

    try {
      const res = await fetch("/crypto-chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message })
      });
      const data = await res.json();

      // Typing animation effect
      const text = data.reply;
      let i = 0;
      aiDiv.innerHTML = `<div class="chat-bubble bot"></div>`;
      const bubble = aiDiv.querySelector(".chat-bubble");
      const interval = setInterval(() => {
        bubble.textContent += text[i];
        chatWindow.scrollTop = chatWindow.scrollHeight;
        i++;
        if(i >= text.length) clearInterval(interval);
      }, 25);

    } catch (err) {
      console.error(err);
      aiDiv.innerHTML = `<div class="chat-bubble bot bg-danger text-white">
        ⚠️ Ooops, something went wrong! Try again later.
      </div>`;
    }
  }

  chatInput.addEventListener("keypress", function (e) {
    if (e.key === "Enter") {
      e.preventDefault();
      sendMessage();
    }
  });
  sendBtn.addEventListener("click", sendMessage);

  // Key checker
  window.checkKeyStrength = function(key) {
    if (key.length < 16) return "⚠️ Weak key!";
    if (!/^[A-Fa-f0-9]+$/.test(key)) return "⚠️ Non-hex characters!";
    return "✅ Key looks strong!";
  };
});
