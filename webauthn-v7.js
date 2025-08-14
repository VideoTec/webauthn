document.getElementById("register").addEventListener("click", async () => {
  try {
    /** @type {PublicKeyCredentialCreationOptions} */
    const creationOptions = JSON.parse(
      /** @type {HTMLTextAreaElement} */ (
        document.getElementById("creation-option")
      ).value
    );

    // @ts-ignore
    creationOptions.challenge = Uint8Array.from(creationOptions.challenge);
    // @ts-ignore
    creationOptions.user.id = Uint8Array.from(creationOptions.user.id);

    const credential = /** @type {PublicKeyCredential} */ (
      await navigator.credentials.create({
        publicKey: creationOptions,
      })
    );
    const credJson = credential.toJSON();
    console.log("Credential JSON:", credJson);
    const publicKeyId = credJson.id;
    const publicKey = credJson.response.publicKey;
    const publicKeyType = credJson.response.publicKeyAlgorithm;

    let credPropsMsg = "没有相关信息";
    if (credJson.clientExtensionResults.credProps) {
      credPropsMsg = "credProps: ";
      if (credJson.clientExtensionResults.credProps.rk === undefined) {
        credPropsMsg += "没有rk";
      } else {
        credPropsMsg += "rk: " + credJson.clientExtensionResults.credProps.rk;
      }
    }

    document.getElementById("public-key-id").textContent = publicKeyId;
    document.getElementById("public-key").textContent = publicKey;
    document.getElementById("public-key-type").textContent = publicKeyType;
    document.getElementById("credProps-rk").textContent = credPropsMsg;
  } catch (error) {
    console.error("Error during registration:", error);
    document.getElementById("create-error-message").textContent = error.message;
  }
});

document.getElementById("login").addEventListener("click", () => {
  login();
});

window.onload = async () => {
  // login();
  console.log(
    "WebAuthn Capabilities:",
    await window.PublicKeyCredential.getClientCapabilities()
  );
  let webauthnCapabilities = "";
  if (!window.PublicKeyCredential) {
    webauthnCapabilities += "不支持WebAuthn API\n";
  } else {
    if (
      await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
    ) {
      webauthnCapabilities += "支持平台身份验证器\n";
    } else {
      webauthnCapabilities += "不支持平台身份验证器\n";
    }
    if (await window.PublicKeyCredential.isConditionalMediationAvailable()) {
      webauthnCapabilities += "支持条件介入\n";
    } else {
      webauthnCapabilities += "不支持条件介入\n";
    }
  }
  document.getElementById("webauthn-feature").textContent =
    webauthnCapabilities;
};

async function login() {
  try {
    document.getElementById("login-error-message").textContent = "";
    /** @type {CredentialRequestOptions} */
    const rqOptions = JSON.parse(
      /** @type {HTMLTextAreaElement} */ (
        document.getElementById("request-option")
      ).value
    );

    rqOptions.publicKey.challenge = Uint8Array.from(
      // @ts-ignore
      rqOptions.publicKey.challenge
    );

    const pkId = base64urlToUint8Array(
      document.getElementById("public-key-id").textContent
    );

    const withCredentials = /** @type {HTMLInputElement} */ (
      document.getElementById("witch-credential")
    ).checked;

    if (withCredentials) {
      rqOptions.publicKey.allowCredentials = [
        {
          id: pkId,
          type: "public-key",
        },
      ];
    }

    const assertion = /** @type {PublicKeyCredential} */ (
      await navigator.credentials.get(rqOptions)
    );
    const assertionJson = assertion.toJSON();
    console.log("Assertion JSON:", assertionJson);
    document.getElementById("user-handle").textContent =
      assertionJson.response.userHandle;
    document.getElementById("client-data").textContent =
      assertionJson.response.clientDataJSON;
    document.getElementById("authenticator-data").textContent =
      assertionJson.response.authenticatorData;
    document.getElementById("signature-data").textContent =
      assertionJson.response.signature;
  } catch (error) {
    console.error("Error during login:", error);
    document.getElementById("login-error-message").textContent = error.message;
  }
}

document.getElementById("verify").addEventListener("click", async () => {
  const clientData = base64urlToUint8Array(
    document.getElementById("client-data").textContent
  );
  const authenticatorData = base64urlToUint8Array(
    document.getElementById("authenticator-data").textContent
  );
  const signature = base64urlToUint8Array(
    document.getElementById("signature-data").textContent
  );
  const signatureRaw = convertASN1toRaw(signature);
  const publicKey = base64urlToUint8Array(
    document.getElementById("public-key").textContent
  );

  const key = await crypto.subtle.importKey(
    "spki",
    publicKey,
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true,
    ["verify"]
  );
  const clientDataHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", clientData)
  );
  const toVerify = concat(authenticatorData, clientDataHash);
  const v = await crypto.subtle.verify(
    {
      name: "ECDSA",
      hash: { name: "SHA-256" },
    },
    key,
    signatureRaw,
    toVerify
  );

  document.getElementById("verify-result").textContent = v
    ? "验证通过"
    : "验证失败";
});

/**
 * Convert an ASN.1 DER encoded signature to a raw format
 * @param {Uint8Array} signature
 * @returns {Uint8Array<ArrayBuffer>}
 */
function convertASN1toRaw(signature) {
  // Convert signature from ASN.1 sequence to "raw" format
  //   const signature = new Uint8Array(signatureBuffer);
  const rStart = signature[4] === 0 ? 5 : 4;
  const rEnd = rStart + 32;
  const sStart = signature[rEnd + 2] === 0 ? rEnd + 3 : rEnd + 2;
  const r = signature.slice(rStart, rEnd);
  const s = signature.slice(sStart);
  return new Uint8Array([...r, ...s]);
}

/**
 * Concatenate two Uint8Arrays
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {Uint8Array<ArrayBuffer>}
 */
function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/**
 * Convert a base64url encoded string to a Uint8Array
 * @param {string} b64url
 * @returns {Uint8Array<ArrayBuffer>}
 */
function base64urlToUint8Array(b64url) {
  // 1) base64url -> base64（替换 -/_，补齐 = 填充）
  const base64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const padding = "=".repeat((4 - (base64.length % 4)) % 4);
  const normalized = base64 + padding;

  // 2) 解码为二进制字符串（优先用 atob，Node 环境下用 Buffer）
  let binary;
  if (typeof atob === "function") {
    binary = atob(normalized);
  } else {
    binary = Buffer.from(normalized, "base64").toString("binary");
  }

  // 3) 二进制字符串 -> Uint8Array
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
