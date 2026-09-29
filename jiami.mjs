#!/usr/bin/env node
/**
 * PNG 无损加密：对文件字节做 AES-256-GCM，解密结果与原 PNG 逐字节一致。
 * 目录会递归处理，加密写到同目录的 .jpng，解密写回同目录的 .png，不删除原文件。
 *
 *   node jiami.mjs encrypt <目录或.png> --password 密码
 *   node jiami.mjs decrypt <目录或.jpng> --password 密码
 */

import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { extname, join } from 'node:path';

const MAGIC = Buffer.from('JPNG');
const VERSION = 1;
const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;
const HEADER_LEN = MAGIC.length + 1 + SALT_LEN + IV_LEN + TAG_LEN;
const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function usage() {
  console.error(`用法:
  node jiami.mjs encrypt <目录或.png> [输出.jpng] --password <密码>
  node jiami.mjs decrypt <目录或.jpng> [输出.png] --password <密码>
目录会递归处理。加密生成同路径 .jpng，解密生成同路径 .png，不删除原文件。`);
  process.exit(1);
}

function parseArgs(argv) {
  const args = argv.slice(2);
  const flag = args.indexOf('--password');
  let password;
  if (flag !== -1) {
    password = args[flag + 1];
    args.splice(flag, 2);
  }
  const [command, input, output] = args;
  return { command, input, output, password };
}

function withExt(file, ext) {
  return file.slice(0, -extname(file).length) + ext;
}

function listFiles(dir, ext) {
  return readdirSync(dir, { recursive: true })
    .map((rel) => join(dir, rel))
    .filter((file) => statSync(file).isFile() && extname(file).toLowerCase() === ext);
}

function collectJobs(command, input, output) {
  const fromExt = command === 'encrypt' ? '.png' : '.jpng';
  const toExt = command === 'encrypt' ? '.jpng' : '.png';
  const info = statSync(input);
  if (info.isDirectory()) {
    if (output) throw new Error('目录模式不需要单独的输出路径');
    return listFiles(input, fromExt).map((src) => ({ src, dest: withExt(src, toExt) }));
  }
  if (!info.isFile()) throw new Error('路径不是文件或目录');
  if (extname(input).toLowerCase() !== fromExt) {
    throw new Error(`单文件${command === 'encrypt' ? '加密' : '解密'}需要 ${fromExt} 文件`);
  }
  return [{ src: input, dest: output || withExt(input, toExt) }];
}

function deriveKey(password, salt) {
  return scryptSync(password, salt, KEY_LEN);
}

function encryptPng(png, password) {
  if (png.length < PNG_SIG.length || !png.subarray(0, PNG_SIG.length).equals(PNG_SIG)) {
    throw new Error('输入不是 PNG 文件');
  }
  const salt = randomBytes(SALT_LEN);
  const iv = randomBytes(IV_LEN);
  const key = deriveKey(password, salt);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([cipher.update(png), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([MAGIC, Buffer.from([VERSION]), salt, iv, tag, body]);
}

function decryptPng(blob, password) {
  if (blob.length < HEADER_LEN || !blob.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new Error('不是本工具生成的加密文件');
  }
  if (blob[MAGIC.length] !== VERSION) {
    throw new Error(`不支持的版本: ${blob[MAGIC.length]}`);
  }
  let offset = MAGIC.length + 1;
  const salt = blob.subarray(offset, offset += SALT_LEN);
  const iv = blob.subarray(offset, offset += IV_LEN);
  const tag = blob.subarray(offset, offset += TAG_LEN);
  const body = blob.subarray(offset);
  const decipher = createDecipheriv('aes-256-gcm', deriveKey(password, salt), iv);
  decipher.setAuthTag(tag);
  let png;
  try {
    png = Buffer.concat([decipher.update(body), decipher.final()]);
  } catch {
    throw new Error('解密失败：密码错误或文件已损坏');
  }
  if (png.length < PNG_SIG.length || !png.subarray(0, PNG_SIG.length).equals(PNG_SIG)) {
    throw new Error('解密结果不是 PNG');
  }
  return png;
}

function runJob(command, src, dest, password) {
  if (command === 'encrypt') {
    const png = readFileSync(src);
    writeFileSync(dest, encryptPng(png, password));
    console.log(`[jiami] 已加密 ${src} -> ${dest} (${png.length} 字节)`);
    return;
  }
  const png = decryptPng(readFileSync(src), password);
  writeFileSync(dest, png);
  console.log(`[jiami] 已解密 ${src} -> ${dest} (${png.length} 字节)`);
}

function main() {
  const { command, input, output, password } = parseArgs(process.argv);
  if ((command !== 'encrypt' && command !== 'decrypt') || !input || !password) usage();
  let jobs;
  try {
    jobs = collectJobs(command, input, output);
  } catch (err) {
    console.error(`[jiami] ${err.message}`);
    process.exit(1);
  }
  if (jobs.length === 0) {
    console.error(`[jiami] 没有找到 ${command === 'encrypt' ? '.png' : '.jpng'} 文件`);
    process.exit(1);
  }
  let failed = 0;
  for (const { src, dest } of jobs) {
    try {
      runJob(command, src, dest, password);
    } catch (err) {
      failed += 1;
      console.error(`[jiami] 失败 ${src}：${err.message}`);
    }
  }
  console.log(`[jiami] 完成：成功 ${jobs.length - failed}，失败 ${failed}`);
  if (failed) process.exit(1);
}

main();
