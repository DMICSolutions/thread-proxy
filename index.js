import express from "express";
import fetch from "node-fetch";

const app = express();
app.use(express.json({ limit: "10mb" }));

// restrict access with a shared secret, optional but smart
const SECRET = process.env.PROXY_SECRET;

app.all("*", async (req, res) => {
  if (req.headers["x-proxy-secret"] !== SECRET) {
    return res.status(403).send("Forbidden");
  }

  try {
    const targetUrl = "https://" + process.env.PROXY_HOST + req.originalUrl;
    const response = await fetch(targetUrl, {
      method: req.method,
      headers: { ...req.headers, host: process.env.PROXY_HOST },
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
app.listen(PORT, () => console.log(`Proxy running on port ${PORT}`));
