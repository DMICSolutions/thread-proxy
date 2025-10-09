import express from "express";
import fetch from "node-fetch";

const app = express();
app.use(express.json({ limit: "1mb" }));

const SECRET = process.env.PROXY_SECRET || "change_me";

// only handle routes that start with /proxy
app.all("/proxy/*", async (req, res) => {
  if (req.headers["x-proxy-secret"] !== SECRET) {
    return res.status(403).send("Forbidden");
  }

  try {
    // remove "/proxy" from the start of the path before forwarding
    const targetPath = req.originalUrl.replace(/^\/proxy/, "");
    const targetUrl = "https://" + process.env.PROXY_HOST + targetPath;

    const response = await fetch(targetUrl, {
      method: req.method,
      headers: { ...req.headers, host: process.env.PROXY_HOST, "accept-encoding": "identity" },
      body: ["GET", "HEAD"].includes(req.method) ? undefined : JSON.stringify(req.body),
    });

    res.status(response.status);
    response.headers.forEach((v, k) => res.setHeader(k, v));
    response.body.pipe(res);
  } catch (err) {
    res.status(500).send("Proxy error");
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Proxy listening on port ${PORT}`));
