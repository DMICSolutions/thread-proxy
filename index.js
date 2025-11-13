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
    // Express behind reverse proxies? uncomment next line if needed:
    // app.set('trust proxy', true);
    const remoteIP = req.ip.replace("::ffff:", ""); // normalize IPv4-in-IPv6
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
        // remove "/proxy" from the start of the path before forwarding
        const targetPath = req.originalUrl.replace(/^\/proxy/, "");
        const targetUrl = "https://" + process.env.PROXY_HOST + targetPath;
        const urlObj = new URL(targetUrl);

        const rawHeaders = {
            ...req.headers,
            host: urlObj.host,
            "accept-encoding": "identity"
        };

        // strip nonsense for GET/HEAD
        if (["GET", "HEAD"].includes(req.method)) {
            delete rawHeaders["content-length"];
            delete rawHeaders["content-type"];
            delete rawHeaders["transfer-encoding"];
        }

        const response = await fetch(targetUrl, {
            method: req.method,
            headers: rawHeaders,
            body: ["GET", "HEAD"].includes(req.method) ? undefined : JSON.stringify(req.body)
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
    console.log(`Proxy listening on port ${PORT}, allowed IPs: ${ALLOWED_IPS.join(", ") || "none"}`)
);
