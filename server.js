import express from "express";
import dotenv from "dotenv";
dotenv.config();
import "dotenv/config";
import express from "express";
import { makePool } from "./db.js";
import { runDomain, runIP, runKeyword, runX } from "./connectors.js";

const app = express();
app.use(express.json({ limit: "256kb" }));

const pool = makePool();

function requireToken(req, res, next) {
  const token = req.query.token || req.headers["x-cron-token"];
  if (!process.env.CRON_TOKEN || token !== process.env.CRON_TOKEN) {
    return res.status(403).send("forbidden");
  }
  next();
}

app.get("/", (_, res) => res.json({ ok: true, service: "iamx-api" }));
app.get("/health", (_, res) => res.json({ ok: true }));

app.get("/targets", async (_, res) => {
  const [rows] = await pool.query("SELECT * FROM targets ORDER BY created_at DESC");
  res.json({ targets: rows });
});

app.post("/targets", async (req, res) => {
  const { type, value } = req.body || {};
  if (!["domain", "ip", "keyword", "x"].includes(type)) return res.status(400).send("bad type");
  if (!value || String(value).length > 255) return res.status(400).send("bad value");
  await pool.query(
    "INSERT INTO targets(type,value) VALUES(?,?) ON DUPLICATE KEY UPDATE is_enabled=1",
    [type, String(value).trim()]
  );
  res.json({ ok: true });
});

app.post("/targets/:id/toggle", async (req, res) => {
  const id = Number(req.params.id);
  await pool.query("UPDATE targets SET is_enabled = 1 - is_enabled WHERE id=?", [id]);
  res.json({ ok: true });
});

app.delete("/targets/:id", async (req, res) => {
  const id = Number(req.params.id);
  await pool.query("DELETE FROM targets WHERE id=?", [id]);
  res.json({ ok: true });
});

app.get("/findings", async (req, res) => {
  const q = String(req.query.q || "").trim();
  const sev = String(req.query.sev || "").trim();
  const params = [];
  let where = "1=1";

  if (q) {
    where += " AND (t.value LIKE ? OR f.title LIKE ? OR f.details LIKE ?)";
    params.push(`%${q}%`, `%${q}%`, `%${q}%`);
  }
  if (sev) {
    where += " AND f.severity=?";
    params.push(sev);
  }

  const [rows] = await pool.query(
    `SELECT f.*, t.type as target_type, t.value as target_value
     FROM findings f JOIN targets t ON t.id=f.target_id
     WHERE ${where}
     ORDER BY f.observed_at DESC
     LIMIT 100`,
    params
  );

  res.json({ findings: rows });
});

async function writeFindings(target, findings) {
  const now = new Date();
  for (const f of findings) {
    await pool.query(
      "INSERT IGNORE INTO findings(target_id,source,severity,title,details,dedupe_key,observed_at) VALUES(?,?,?,?,?,?,?)",
      [target.id, f.source, f.severity, f.title, f.details, f.dedupe_key, now]
    );
  }
  await pool.query("UPDATE targets SET last_run_at=NOW() WHERE id=?", [target.id]);
}

async function runTarget(t) {
  if (!t.is_enabled) return [];
  if (t.type === "domain") return await runDomain(t);
  if (t.type === "ip") return await runIP(t);
  if (t.type === "keyword") return await runKeyword(t);
  if (t.type === "x") return await runX(t);
  return [];
}

app.post("/run/target/:id", async (req, res) => {
  const id = Number(req.params.id);
  const [rows] = await pool.query("SELECT * FROM targets WHERE id=?", [id]);
  const t = rows[0];
  if (!t) return res.status(404).send("not found");
  const f = await runTarget(t);
  await writeFindings(t, f);
  res.json({ ok: true, count: f.length });
});

app.post("/run/all", async (req, res) => {
  const [rows] = await pool.query("SELECT * FROM targets WHERE is_enabled=1 ORDER BY id DESC");
  let total = 0;
  for (const t of rows) {
    const f = await runTarget(t);
    await writeFindings(t, f);
    total += f.length;
  }
  res.json({ ok: true, total });
});

app.get("/cron/run", requireToken, async (req, res) => {
  const [rows] = await pool.query("SELECT * FROM targets WHERE is_enabled=1");
  let ran = 0, total = 0;

  for (const t of rows) {
    const [d] = await pool.query(
      "SELECT TIMESTAMPDIFF(MINUTE, COALESCE(?, '1970-01-01'), NOW()) as diff",
      [t.last_run_at]
    );
    if (Number(d[0].diff) < Number(t.interval_min)) continue;

    const f = await runTarget(t);
    await writeFindings(t, f);
    total += f.length;
    ran++;
  }

  res.json({ ok: true, ran, total });
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log("iamx api listening", port));

const express = require("express");
const app = express();

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

app.listen(3000, () => {
  console.log("Server running");

});
