// Gera index.html: tela de login + src/carta.html criptografada (AES-GCM).
// Uso: node build.mjs usuario:senha[:papel] [outro:senha[:papel]] ...
// A carta só existe no repositório como texto cifrado; sem usuário e senha não há o que ler.
import { readFileSync, writeFileSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';

const ITER = 310000;
const enc = new TextEncoder();
const b64 = (buf) => Buffer.from(buf).toString('base64');

const sha256 = async (s) => b64(await crypto.subtle.digest('SHA-256', enc.encode(s)));

async function deriveKey(user, pass, salt) {
  const base = await crypto.subtle.importKey('raw', enc.encode(`${user}\n${pass}`), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
}

const specs = process.argv.slice(2);
if (!specs.length) {
  console.error('Uso: node build.mjs usuario:senha[:papel] ...');
  process.exit(1);
}

const html = readFileSync(new URL('./src/carta.html', import.meta.url), 'utf8');
const salt = crypto.getRandomValues(new Uint8Array(16));

const users = {};
for (const spec of specs) {
  const [user, pass, role = 'viewer'] = spec.split(':');
  if (!user || !pass) throw new Error(`Credencial inválida: ${spec}`);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(user, pass, salt);
  const payload = JSON.stringify({ attrs: { user, role }, html });
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(payload));
  users[await sha256(user.toLowerCase())] = { iv: b64(iv), ct: b64(ct) };
}

const db = { iter: ITER, salt: b64(salt), users };
const shell = readFileSync(new URL('./src/login.template.html', import.meta.url), 'utf8');
writeFileSync(new URL('./index.html', import.meta.url), shell.replace('/*__DB__*/null', JSON.stringify(db)));
console.log(`index.html gerado com ${specs.length} usuário(s).`);
