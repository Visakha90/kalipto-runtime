import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { exec } from "child_process";

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.RUNTIME_API_KEY;

function auth(req, res, next) {
const key =
req.headers["x-api-key"] ||
req.headers["authorization"];

if (!API_KEY) return next();

if (!key || !String(key).includes(API_KEY)) {
return res.status(401).json({
error: "unauthorized"
});
}

next();
}

app.get("/health", (req, res) => {
res.json({
status: "ok",
service: "kalipto-runtime",
version: "1.0.0",
uptimeSec: process.uptime()
});
});

app.post("/execute", auth, (req, res) => {
const command = req.body.command;

if (!command) {
return res.status(400).json({
error: "command required"
});
}

exec(
command,
{ timeout: 30000 },
(error, stdout, stderr) => {
res.json({
ok: !error,
stdout,
stderr,
exitCode: error?.code ?? 0
});
}
);
});

app.listen(PORT, () => {
console.log(
`Kalipto Runtime running on ${PORT}`
);
});
