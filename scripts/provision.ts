import "dotenv/config";
import { Client } from "pg";
import { readFileSync } from "node:fs";
const ident = (v: string) => '"' + v.replaceAll('"', '""') + '"';
async function main() {
  const client = new Client({
    connectionString: process.env.MIGRATION_DATABASE_URL,
  });
  await client.connect();
  try {
    const url = new URL(process.env.DATABASE_URL!);
    const user = decodeURIComponent(url.username),
      password = decodeURIComponent(url.password);
    if (!/^[A-Za-z0-9_]+$/.test(user)) throw Error("Invalid runtime role");
    const exists = await client.query(
      "SELECT 1 FROM pg_roles WHERE rolname=$1",
      [user],
    );
    if (!exists.rowCount)
      await client.query(`CREATE ROLE ${ident(user)} LOGIN`);
    await client.query(
      `ALTER ROLE ${ident(user)} PASSWORD '${password.replaceAll("'", "''")}'`,
    );
    await client.query(
      `GRANT CONNECT ON DATABASE ${ident(url.pathname.slice(1))} TO ${ident(user)}`,
    );
    await client.query(`GRANT USAGE ON SCHEMA public TO ${ident(user)}`);
    await client.query(
      `GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO ${ident(user)}`,
    );
    await client.query(
      `REVOKE UPDATE,DELETE,TRUNCATE ON audit_logs,security_events FROM ${ident(user)}`,
    );
    await client.query(`REVOKE ALL ON _prisma_migrations FROM ${ident(user)}`);
    await client.query(
      `REVOKE INSERT,UPDATE,DELETE ON signing_keys FROM ${ident(user)}`,
    );
    const store = JSON.parse(readFileSync(process.env.KEYSTORE_FILE!, "utf8"));
    for (const k of store.keys)
      await client.query(
        'INSERT INTO signing_keys (id,purpose,"publicKey",status,"notBefore","verifyUntil") VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (id) DO NOTHING',
        [
          k.id,
          k.purpose,
          k.publicKey,
          k.status,
          new Date(k.notBefore * 1000),
          new Date(k.verifyUntil * 1000),
        ],
      );
    console.log(
      "Runtime DB permissions and public signing metadata provisioned",
    );
  } finally {
    await client.end();
  }
}
main().catch(() => {
  console.error("Provision failed");
  process.exit(1);
});
