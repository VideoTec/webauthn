document.getElementById("register").addEventListener("click", async () => {
  /** @type {PublicKeyCredentialCreationOptions} */
  const publicKey = {
    // challenge: new Uint8Array(32),
    challenge: new Uint8Array([7, 8, 9, 10, 11]),
    rp: {
      name: "Example Corp",
    },
    user: {
      id: new Uint8Array([1, 2, 3, 4, 5, 3]),
      name: "user2@example.com",
      displayName: "Example User",
    },
    authenticatorSelection: {
      residentKey: "required",
    },
    pubKeyCredParams: [
      {
        type: "public-key",
        alg: -7,
      },
      {
        type: "public-key",
        alg: -8,
      },
      {
        type: "public-key",
        alg: -257,
      },
    ],
  };

  const credential = /** @type {PublicKeyCredential} */ (
    await navigator.credentials.create({
      publicKey,
    })
  );
  console.log(credential.toJSON());
});

document.getElementById("login").addEventListener("click", async () => {
  /** @type {PublicKeyCredentialRequestOptions} */
  const publicKey = {
    challenge: new Uint8Array([7, 8, 9, 10, 11]),
  };
  const assertion = /** @type {PublicKeyCredential} */ (
    await navigator.credentials.get({ publicKey, mediation: "required" })
  );
  console.log(assertion.toJSON());
});
