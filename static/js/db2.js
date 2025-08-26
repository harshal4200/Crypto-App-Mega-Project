<!-- Decrypt Section -->
<div class="form-group">
  <label for="decryptInput">Enter text to Decrypt:</label>
  <input type="text" id="decryptInput" class="form-control" placeholder="Enter encrypted text" />
</div>
<button type="button" id="decryptBtn" class="btn btn-warning">Decrypt</button>

<!-- Output Section -->
  <><div class="form-group mt-3">
    <label>Decrypted Message:</label>
    <input type="text" id="decryptOutput" class="form-control" readonly />
    <button type="button" id="copyBtn" class="btn btn-secondary mt-2">Copy</button>
  </div><script>
// Example decryption function (yaha apna logic dalna hoga)
      function decryptText(encrypted) {
        // Agar tu hash password decrypt karna soch raha hai to wo possible nahi hai.
        // Lekin agar simple encoding/logic hai to yaha change kar sakta hai
      }
    // Agar tu hash password decrypt karna soch raha hai to wo possible nahi hai.
      // Lekin agar simple encoding/logic hai to yaha change kar sakta hai
      return atob(encrypted); // Base64 example ke liye
      }

      // Decrypt Button Event
      document.getElementById("decryptBtn").addEventListener("click", function() { }
      const encrypted = document.getElementById("decryptInput").value.trim();
      if (encrypted === "") {alert("Please enter encrypted text!")};
      return;
      }
      try { }
      const decrypted = decryptText(encrypted);
      document.getElementById("decryptOutput").value = decrypted;
      } catch (err) {alert("Invalid encrypted text!")};
      }
      });

      // Copy Button Event
      document.getElementById("copyBtn").addEventListener("click", function() { }
      const output = document.getElementById("decryptOutput");
      if (output.value.trim() === "") {alert("Nothing to copy!")};
      return;
      }
      output.select();
      document.execCommand("copy");
      alert("Copied: " + output.value);
      });
    </script></>
