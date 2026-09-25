#!/usr/bin/env node

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const outputDir = process.argv[2];
const password = process.argv[3];
const iterations = 210000;

if (!outputDir || !password) {
  console.error("Usage: node scripts/protect-content.js <hugo-output-dir> <password>");
  process.exit(1);
}

const base64 = (value) => value.toString("base64");

function deriveKey(passwordText, salt) {
  return crypto.pbkdf2Sync(passwordText, salt, iterations, 32, "sha256");
}

function encrypt(html) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = deriveKey(password, salt);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(html, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  const payload = {
    version: 1,
    algorithm: "AES-GCM",
    iterations,
    salt: base64(salt),
    iv: base64(iv),
    tag: base64(tag),
    data: base64(encrypted),
  };

  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
}

function filesIn(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const entryPath = path.join(directory, entry.name);
    return entry.isDirectory() ? filesIn(entryPath) : [entryPath];
  });
}

let protectedPages = 0;

for (const filePath of filesIn(outputDir)) {
  if (path.extname(filePath) !== ".html") {
    continue;
  }

  let html = fs.readFileSync(filePath, "utf8");
  if (!html.includes('data-protected-content="true"')) {
    continue;
  }

  const sourcePattern = /<div class="protected-content-source"[^>]*>\s*<span data-protected-content-start><\/span>([\s\S]*?)<span data-protected-content-end><\/span>\s*<\/div>/;
  const sourceMatch = html.match(sourcePattern);
  if (!sourceMatch) {
    throw new Error(`Protected content markers not found in ${filePath}`);
  }

  const ciphertext = encrypt(sourceMatch[1]);
  html = html.replace(
    sourcePattern,
    `<div class="protected-content-ciphertext" data-protected-ciphertext="${ciphertext}"></div>`,
  );

  html = html.replace(
    /<meta\b[^>]*(?:name|property)="(?:description|og:description|twitter:description)"[^>]*>/gi,
    (tag) => tag.replace(/content="[^"]*"/i, 'content="需要输入密码后阅读"'),
  );

  html = html.replace(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g, (match, jsonText) => {
    try {
      const json = JSON.parse(jsonText);
      if (json && typeof json === "object") {
        if ("articleBody" in json) json.articleBody = "";
        if ("description" in json) json.description = "需要输入密码后阅读";
      }
      return `<script type="application/ld+json">${JSON.stringify(json)}</script>`;
    } catch {
      return match;
    }
  });

  fs.writeFileSync(filePath, html);
  protectedPages += 1;
}

console.log(`Encrypted ${protectedPages} protected page${protectedPages === 1 ? "" : "s"}.`);
