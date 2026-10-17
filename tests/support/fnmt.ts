import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Disposable certificate chains shaped like FNMT-RCM "Persona Física" certificates.
 * Every name carries "PRUEBAS" so no fixture can be mistaken for a real FNMT
 * certificate. 99999999R is the DNI number that Spanish administrations reserve
 * for tests. Nothing generated here is committed.
 */

export function openssl(args: string[], input?: string): Buffer {
  const result = spawnSync("openssl", args, { input });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(result.stderr.toString());
  return result.stdout;
}

function opensslTime(date: Date): string {
  return `${date.toISOString().replace(/[-:T]/g, "").slice(0, 14)}Z`;
}

const day = 86_400_000;

export interface Validity {
  from?: Date;
  to?: Date;
}

interface Issued {
  key: string;
  cert: string;
}

export interface FnmtIdentity {
  /** PKCS#12 with the end-entity key, its certificate, and the CA chain. */
  p12: Buffer;
  /** PEM path of the disposable root, for validators that take trust anchors. */
  root: string;
  subjectCommonName: string;
}

/**
 * Creates root, intermediate, and end-entity certificates in folder.
 * givenName and surnames are upper case, as FNMT issues them.
 */
export function fnmtIdentity(
  folder: string,
  options: {
    givenName: string;
    surnames: string;
    password: string;
    leaf?: Validity;
    intermediate?: Validity;
  },
): FnmtIdentity {
  mkdirSync(folder, { recursive: true });
  const path = (name: string) => join(folder, name);
  const keyFile = (name: string) => {
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    writeFileSync(
      path(name),
      privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
      { mode: 0o600 },
    );
    return path(name);
  };
  const dates = (validity: Validity = {}) => [
    "-not_before",
    opensslTime(validity.from ?? new Date(Date.now() - day)),
    "-not_after",
    opensslTime(validity.to ?? new Date(Date.now() + 365 * day)),
  ];

  const root: Issued = { key: keyFile("root.key"), cert: path("root.pem") };
  openssl([
    ...["req", "-x509", "-new", "-utf8", "-key", root.key],
    ...["-subj", "/C=ES/O=FNMT-RCM PRUEBAS/OU=AC RAIZ FNMT-RCM PRUEBAS"],
    ...dates({ to: new Date(Date.now() + 3650 * day) }),
    ...["-addext", "basicConstraints=critical,CA:TRUE"],
    ...["-addext", "keyUsage=critical,keyCertSign,cRLSign"],
    ...["-out", root.cert],
  ]);

  const issue = (
    name: string,
    subject: string,
    issuer: Issued,
    validity: Validity | undefined,
    extensions: string,
  ): Issued => {
    const issued = { key: keyFile(`${name}.key`), cert: path(`${name}.pem`) };
    writeFileSync(path(`${name}.ext`), extensions);
    const request = openssl([
      ...["req", "-new", "-utf8", "-key", issued.key, "-subj", subject],
    ]).toString();
    openssl(
      [
        ...["x509", "-req", "-CA", issuer.cert, "-CAkey", issuer.key],
        ...["-set_serial", `0x${Date.now().toString(16)}${name.length}`],
        ...["-extfile", path(`${name}.ext`), ...dates(validity)],
        ...["-out", issued.cert],
      ],
      request,
    );
    return issued;
  };

  const intermediate = issue(
    "intermediate",
    "/C=ES/O=FNMT-RCM PRUEBAS/OU=Ceres/CN=AC FNMT Usuarios PRUEBAS",
    root,
    options.intermediate,
    [
      "basicConstraints=critical,CA:TRUE,pathlen:0",
      "keyUsage=critical,keyCertSign,cRLSign",
      "subjectKeyIdentifier=hash",
      "authorityKeyIdentifier=keyid",
    ].join("\n"),
  );

  const dni = "99999999R";
  const subjectCommonName = `${options.surnames} ${options.givenName} - ${dni}`;
  const leaf = issue(
    "leaf",
    [
      "/C=ES",
      `serialNumber=IDCES-${dni}`,
      `GN=${options.givenName}`,
      `SN=${options.surnames}`,
      `CN=${subjectCommonName}`,
    ].join("/"),
    intermediate,
    options.leaf,
    [
      "basicConstraints=critical,CA:FALSE",
      "keyUsage=critical,digitalSignature,nonRepudiation,keyEncipherment",
      "extendedKeyUsage=clientAuth,emailProtection",
      "subjectKeyIdentifier=hash",
      "authorityKeyIdentifier=keyid",
    ].join("\n"),
  );

  writeFileSync(
    path("chain.pem"),
    readFileSync(intermediate.cert, "utf8") + readFileSync(root.cert, "utf8"),
  );
  openssl([
    ...["pkcs12", "-export", "-inkey", leaf.key, "-in", leaf.cert],
    ...["-certfile", path("chain.pem"), "-name", subjectCommonName],
    ...["-passout", `pass:${options.password}`, "-out", path("identity.p12")],
  ]);
  return {
    p12: readFileSync(path("identity.p12")),
    root: root.cert,
    subjectCommonName,
  };
}
