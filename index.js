import express from "express";
import fetch from "node-fetch";

const app = express();
app.set("trust proxy", true);
app.use(express.json({ limit: "1mb" }));

const SECRET = process.env.PROXY_SECRET || "change_me";

// Comma-separated list of allowed source IPs (Logic App outbound IPs)
const ALLOWED_IPS = (process.env.ALLOWED_IPS || "")
    .split(",")
    .map(ip => ip.trim())
    .filter(Boolean);

// Middleware: block everything except allowed IPs
app.use((req, res, next) => {
    const remoteIP = req.ip.replace("::ffff:", "");
    if (ALLOWED_IPS.length && !ALLOWED_IPS.includes(remoteIP)) {
        console.warn(`Blocked request from ${remoteIP}`);
        return res.status(403).send("Forbidden (unauthorized IP)");
    }
    next();
});

// only handle routes that start with /proxy
app.all("/proxy/*", async (req, res) => {
    if (req.headers["x-proxy-secret"] !== SECRET) {
        return res.status(403).send("Forbidden (invalid secret)");
    }

    try {
        // strip "/proxy"
        const targetPath = req.originalUrl.replace(/^\/proxy/, "");

        // choose host based on method
        const upstreamHost =
            req.method === "GET"
                ? "login.microsoftonline.com"
                : process.env.PROXY_HOST;

        const targetUrl = "https://" + upstreamHost + targetPath;
        const urlObj = new URL(targetUrl);

        const rawHeaders = {
            ...req.headers,
            host: urlObj.host,
            "accept-encoding": "identity"
        };

        if (["GET", "HEAD"].includes(req.method)) {
            delete rawHeaders["content-length"];
            delete rawHeaders["content-type"];
            delete rawHeaders["transfer-encoding"];
        }

        const response = await fetch(targetUrl, {
            method: req.method,
            headers: rawHeaders,
            body:
                ["GET", "HEAD"].includes(req.method)
                    ? undefined
                    : JSON.stringify(req.body)
        });

        res.status(response.status);
        response.headers.forEach((v, k) => res.setHeader(k, v));
        response.body.pipe(res);
    } catch (err) {
        console.error("Proxy error:", err);
        res.status(500).send("Proxy error");
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
    console.log(
        `Proxy listening on port ${PORT}, allowed IPs: ${ALLOWED_IPS.join(", ") || "none"
        }`
    )
);
