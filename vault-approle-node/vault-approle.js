/**
 * vault-approle.js
 *
 * Authenticates with HashiCorp Vault using the AppRole auth method,
 * then reads AWS static credentials from the Vault AWS Secrets Engine.
 *
 * Library: node-vault (https://github.com/kr1sp1n/node-vault)
 * Install:  npm install node-vault
 *
 * Prerequisites:
 *   - Vault running at VAULT_ADDR (default: http://127.0.0.1:8200)
 *   - ROLE_ID   env var — retrieved from the Jupyter notebook via vault CLI
 *   - SECRET_ID env var — retrieved from the Jupyter notebook via vault CLI
 *
 * No root/admin token is used by this script.
 */

"use strict";

const vault = require("node-vault");

// ── Configuration ────────────────────────────────────────────────────────────
const VAULT_ADDR  = process.env.VAULT_ADDR  || "http://127.0.0.1:8200";
const ROLE_ID     = process.env.ROLE_ID;
const SECRET_ID   = process.env.SECRET_ID;
const SECRET_PATH = process.env.SECRET_PATH || "aws/static-creds/app-test";

if (!ROLE_ID || !SECRET_ID) {
  console.error("[ERROR] ROLE_ID and SECRET_ID environment variables are required.");
  console.error("        Run the Jupyter notebook cell to obtain and export them.");
  process.exit(1);
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function log(section, data) {
  console.log(`\n=== ${section} ===`);
  console.log(JSON.stringify(data, null, 2));
}

// ── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  // Unauthenticated client — used only to perform the AppRole login
  const client = vault({ apiVersion: "v1", endpoint: VAULT_ADDR });

  console.log(`Vault address : ${VAULT_ADDR}`);
  console.log(`Secret path   : ${SECRET_PATH}`);
  console.log(`Role ID       : ${ROLE_ID}`);
  console.log(`Secret ID     : ${SECRET_ID.substring(0, 8)}... (truncated)`);

  // ── Step 1: AppRole Login ─────────────────────────────────────────────────
  console.log("\n[1] Logging in with AppRole...");
  const loginRes = await client.approleLogin({
    role_id:   ROLE_ID,
    secret_id: SECRET_ID,
  });

  const appRoleToken = loginRes.auth.client_token;
  const tokenTTL     = loginRes.auth.lease_duration;
  const policies     = loginRes.auth.policies;

  console.log(`    client_token   : ${appRoleToken.substring(0, 12)}... (truncated)`);
  console.log(`    lease_duration : ${tokenTTL}s`);
  console.log(`    policies       : ${policies.join(", ")}`);

  // ── Step 2: Read the secret using the AppRole token ───────────────────────
  console.log(`\n[2] Reading secret at "${SECRET_PATH}" using AppRole token...`);
  const appClient = vault({
    apiVersion: "v1",
    endpoint: VAULT_ADDR,
    token: appRoleToken,
  });

  const secretRes  = await appClient.read(SECRET_PATH);

  const expiration   = secretRes.data.expiration;
  const expiresAt    = expiration ? new Date(expiration) : null;
  const secondsLeft  = expiresAt ? Math.round((expiresAt - Date.now()) / 1000) : null;
  const ttlHuman     = secondsLeft !== null
    ? `${Math.floor(secondsLeft / 60)}m ${secondsLeft % 60}s`
    : "unknown";

  log("AWS Static Credentials", {
    access_key:        secretRes.data.access_key,
    secret_key:        secretRes.data.secret_key,
    expires_at:        expiresAt ? expiresAt.toISOString() : "unknown",
    expires_in:        ttlHuman,
  });

  console.log("\nDone. Use the credentials above to call AWS APIs.");
}

main().catch((err) => {
  console.error("\n[ERROR]", err.message || err);
  process.exit(1);
});
