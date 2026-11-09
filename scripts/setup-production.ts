import { existsSync, readFileSync, writeFileSync, mkdirSync, renameSync } from "node:fs";
import { productionMaterial } from "./production-material";

// The mount contains installer data only; no database access is required here.
const destination = "/setup";
if (existsSync(destination + "/material")) {
  console.log("Existing production material preserved.");
} else {
  const material = productionMaterial(JSON.parse(readFileSync(destination + "/input.json", "utf8")));
  const staging = destination + "/staging-" + process.pid;
  mkdirSync(staging, { mode: 0o700 });
  const write = (name: string, value: string) => writeFileSync(staging + "/" + name, value, { mode: 0o600, flag: "wx" });
  write("keystore.json", JSON.stringify(material.store, null, 2));
  write("manifest-root.pem", material.root.privateKey);
  write("manifest-root-public.pem", material.root.publicKey);
  write("production.env", material.env);
  renameSync(staging, destination + "/material");
  console.log("Production material generated; no secrets printed.");
}
