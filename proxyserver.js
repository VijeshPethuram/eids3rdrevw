const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const moment = require('moment-timezone');

const app = express();
const PORT = 5551; // Proxy Server runs on a different port
const HOSPITAL_SERVER_URL = "http://localhost:5550"; // URL of the Hospital Server
const TRA_URL = "http://localhost:6000"; // URL of the Trusted Registration Authority
const ENTITY_ID = "proxy_server_1"; // Unique ID for the Proxy Server
let SESSION_KEY = null; // Session key for secure communication

// Middleware to parse JSON requests
app.use(express.json());

// 🔹 Register with the Trusted Registration Authority (TRA)
async function registerWithTRA() {
    try {
        const response = await axios.post(`${TRA_URL}/register`, {
            entity_id: ENTITY_ID,
            entity_type: "proxy_server"
        });
        SESSION_KEY = response.data.session_key;
        console.log("Proxy server registered with TRA. SKEY:", SESSION_KEY);
    } catch (error) {
        console.error("TRA registration failed. Retrying...", error.message);
        setTimeout(registerWithTRA, 5000); // Retry after 5 seconds
    }
}

// 🔹 Generate HMAC for secure communication
function generateHMAC(nonce) {
    return crypto.createHmac('sha256', SESSION_KEY)
                 .update(nonce)
                 .digest('hex');
}

// 🔹 Validate incoming requests using HMAC
function validateRequest(headers) {
    const entityId = headers["entity-id"];
    const nonce = headers["nonce"];
    const receivedHmac = headers["hmac"];

    if (!entityId || !nonce || !receivedHmac) {
        return false;
    }

    const computedHmac = generateHMAC(nonce);
    return crypto.timingSafeEqual(Buffer.from(receivedHmac), Buffer.from(computedHmac));
}

// 🔹 Forward requests to the Hospital Server
async function forwardRequest(req, res, endpoint) {
    try {
        // Validate the request
        if (!validateRequest(req.headers)) {
            return res.status(401).json({ message: 'Authentication failed' });
        }

        // Forward the request to the Hospital Server
        print("Forwarding a request to the Original hospital server.")
        const response = await axios.post(`${HOSPITAL_SERVER_URL}${endpoint}`, req.body, {
            headers: {
                "Entity-ID": ENTITY_ID,
                "Nonce": crypto.randomBytes(16).toString('hex'),
                "HMAC": generateHMAC(crypto.randomBytes(16).toString('hex'))
            }
        });

        // Return the response from the Hospital Server
        res.status(response.status).json(response.data);
    } catch (error) {
        console.error("Error forwarding request:", error.message);
        res.status(500).json({ message: 'Internal server error' });
    }
}

// 🔹 Forward sensor data to the Hospital Server
app.post('/data', (req, res) => {
    forwardRequest(req, res, '/data');
});

// 🔹 Forward intrusion alerts to the Hospital Server
app.post('/error', (req, res) => {
    forwardRequest(req, res, '/error');
});

// 🔹 Retrieve all sensor data from the Hospital Server
app.get('/data', async (req, res) => {
    try {
        const response = await axios.get(`${HOSPITAL_SERVER_URL}/data`);
        res.status(response.status).json(response.data);
    } catch (error) {
        console.error("Error retrieving sensor data:", error.message);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// 🔹 Retrieve sensor data for a specific ID from the Hospital Server
app.get('/data/:id', async (req, res) => {
    try {
        const response = await axios.get(`${HOSPITAL_SERVER_URL}/data/${req.params.id}`);
        res.status(response.status).json(response.data);
    } catch (error) {
        console.error("Error retrieving sensor data:", error.message);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// 🔹 Serve Web UI (Proxy for the Hospital Server's UI)
app.get('/', async (req, res) => {
    try {
        const response = await axios.get(`${HOSPITAL_SERVER_URL}/`);
        res.send(response.data);
    } catch (error) {
        console.error("Error serving Web UI:", error.message);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// 🔹 Get intrusion status from the Hospital Server
app.get('/error-status', async (req, res) => {
    try {
        const response = await axios.get(`${HOSPITAL_SERVER_URL}/error-status`);
        res.status(response.status).json(response.data);
    } catch (error) {
        console.error("Error retrieving intrusion status:", error.message);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Initialize
registerWithTRA();
app.listen(PORT, () => console.log(`Proxy server running on port ${PORT}`));