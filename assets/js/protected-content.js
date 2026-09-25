(() => {
  const sessionKey = "blog-april-password";
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  function readCookie(name) {
    const prefix = `${name}=`;
    const cookie = document.cookie.split("; ").find((value) => value.startsWith(prefix));
    return cookie ? decodeURIComponent(cookie.slice(prefix.length)) : "";
  }

  function writeAuthorization(password) {
    const value = encodeURIComponent(password);
    document.cookie = `${sessionKey}=${value}; path=/; SameSite=Lax`;
    try {
      sessionStorage.setItem(sessionKey, password);
      localStorage.setItem(sessionKey, password);
    } catch {
      // Storage may be blocked; the same-origin cookie is sufficient.
    }
  }

  function clearAuthorization() {
    document.cookie = `${sessionKey}=; Max-Age=0; path=/; SameSite=Lax`;
    try {
      sessionStorage.removeItem(sessionKey);
      localStorage.removeItem(sessionKey);
    } catch {
      // Ignore unavailable browser storage.
    }
  }

  function getAuthorization() {
    const hashParams = new URLSearchParams(window.location.hash.slice(1));
    const hashPassword = hashParams.get("april-access");
    if (hashPassword) {
      try {
        return atob(hashPassword);
      } catch {
        // Ignore malformed hand-off data.
      }
    }
    const cookiePassword = readCookie(sessionKey);
    if (cookiePassword) return cookiePassword;
    try {
      return localStorage.getItem(sessionKey) || sessionStorage.getItem(sessionKey) || "";
    } catch {
      return "";
    }
  }

  function addAuthorizationToLinks(root, password) {
    const encodedPassword = btoa(password);
    root.querySelectorAll("a.entry-link").forEach((link) => {
      const target = new URL(link.getAttribute("href"), window.location.href);
      link.href = `${target.pathname}${target.search}#april-access=${encodeURIComponent(encodedPassword)}`;
    });
  }

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
      writeAuthorization(password);
      if (root.dataset.protectedCategory === "true") {
        addAuthorizationToLinks(rendered, password);
      }
      if (window.location.hash.includes("april-access=")) {
        window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
      }
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

    const previousPassword = getAuthorization();
    if (previousPassword) {
      unlock(previousPassword).catch(() => {
        clearAuthorization();
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
