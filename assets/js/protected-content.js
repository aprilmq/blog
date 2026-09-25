(() => {
  const sessionKey = "blog-april-password";
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  function decodeBase64(value) {
    const binary = atob(value);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  }

  async function decrypt(ciphertext, password) {
    const payload = JSON.parse(decoder.decode(decodeBase64(ciphertext)));
    const salt = decodeBase64(payload.salt);
    const iv = decodeBase64(payload.iv);
    const tag = decodeBase64(payload.tag);
    const data = decodeBase64(payload.data);
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      "PBKDF2",
      false,
      ["deriveKey"],
    );
    const key = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: payload.iterations, hash: "SHA-256" },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
    const encrypted = new Uint8Array(data.length + tag.length);
    encrypted.set(data);
    encrypted.set(tag, data.length);
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted);
    return decoder.decode(plaintext);
  }

  function setupProtectedContent(root) {
    const dialog = root.querySelector("[data-protected-dialog]");
    const form = root.querySelector("[data-protected-form]");
    const input = root.querySelector("[data-protected-input]");
    const error = root.querySelector("[data-protected-error]");
    const lock = root.querySelector("[data-protected-lock]");
    const rendered = root.querySelector("[data-protected-rendered]");
    const ciphertext = root.querySelector("[data-protected-ciphertext]")?.dataset.protectedCiphertext;
    const devPassword = root.dataset.protectedDevPassword;
    const source = root.querySelector(".protected-content-source");
    const devContent = source?.innerHTML
      .replace(/<span data-protected-content-start><\/span>/, "")
      .replace(/<span data-protected-content-end><\/span>/, "");

    if (!dialog || !form || !input || !error || !lock || !rendered || (!ciphertext && !devPassword)) {
      return;
    }

    function showError(message) {
      error.textContent = message;
      error.hidden = false;
    }

    function closeDialog() {
      dialog.hidden = true;
      document.body.classList.remove("protected-content-modal-open");
    }

    async function unlock(password) {
      if (ciphertext) {
        rendered.innerHTML = await decrypt(ciphertext, password);
      } else if (devPassword && password === devPassword) {
        rendered.innerHTML = devContent || "";
      } else {
        throw new Error("Invalid password");
      }
      sessionStorage.setItem(sessionKey, password);
      lock.hidden = true;
      rendered.hidden = false;
      closeDialog();
    }

    root.querySelector("[data-protected-open]")?.addEventListener("click", () => {
      error.hidden = true;
      input.value = "";
      dialog.hidden = false;
      document.body.classList.add("protected-content-modal-open");
      input.focus();
    });

    root.querySelector("[data-protected-cancel]")?.addEventListener("click", () => {
      closeDialog();
    });

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      error.hidden = true;

      if (!ciphertext) {
        showError("文章尚未完成加密，请重新发布后再试。 ");
        return;
      }

      const submit = form.querySelector("button[type=submit]");
      submit.disabled = true;
      try {
        await unlock(input.value);
      } catch {
        showError("密码错误，请重试。 ");
        input.select();
      } finally {
        submit.disabled = false;
      }
    });

    const previousPassword = sessionStorage.getItem(sessionKey);
    if (previousPassword) {
      unlock(previousPassword).catch(() => {
        sessionStorage.removeItem(sessionKey);
        requestAnimationFrame(() => {
          dialog.hidden = false;
          document.body.classList.add("protected-content-modal-open");
          input.focus();
        });
      });
    } else {
      requestAnimationFrame(() => {
        dialog.hidden = false;
        document.body.classList.add("protected-content-modal-open");
        input.focus();
      });
    }
  }

  document.querySelectorAll('[data-protected-content="true"]').forEach(setupProtectedContent);
})();
