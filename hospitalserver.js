const express = require('express');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
const PORT = 5550;
const TRA_URL = "http://localhost:6000";
const ENTITY_ID = "hospital_server_1";
let SESSION_KEY = null;

// Registration with TRA
async function registerWithTRA() {
    try {
        const response = await axios.post(`${TRA_URL}/register`, {
            entity_id: ENTITY_ID,
            entity_type: "hospital_server"
        });
        SESSION_KEY = response.data.session_key;
        console.log("Hospital server registered with TRA");
    } catch (error) {
        console.error("Registration failed:", error.message);
    }
}

// Generate auth headers
function generateAuthHeaders() {
    const nonce = crypto.randomBytes(16).toString('hex');
    const hmac = crypto.createHmac('sha256', SESSION_KEY)
                       .update(nonce)
                       .digest('hex');
    return {
        "Entity-ID": ENTITY_ID,
        "Nonce": nonce,
        "HMAC": hmac
    };
}
let data = {};
let intrusion = false;  

// 🔹 Store Sensor Data Securely
app.post('/data', (req, res) => {
    const { id, bpm } = req.body;

    if (!id || bpm === undefined) {
        return res.status(400).json({ message: 'Invalid input. Please provide id and bpm.' });
    }

    const timestamp = moment().tz("Asia/Kolkata").format('DD-MM-YYYY HH:mm:ss');

    if (!data[id]) {
        data[id] = [];
    }

    data[id].push({ id, timestamp, bpm });

    return res.status(201).json({ message: 'Data added successfully.', d: { id, timestamp, bpm } });
});

// 🔹 Handle Intrusion Alerts
app.post('/error', (req, res) => {
    console.log("🔴 Intrusion detected! Alert sent to hospital authorities.");
    intrusion = true;
    res.status(201).json({ message: 'System intrusion detected!' });
});

// 🔹 Retrieve All Sensor Data
app.get('/data', (req, res) => {
    return res.status(200).json(data);
});

// 🔹 Retrieve Data for Specific Sensor ID
app.get('/data/:id', (req, res) => {
    const { id } = req.params;

    if (!data[id]) {
        return res.status(404).json({ message: 'Data not found.' });
    }

    return res.status(200).json(data[id]);
});

// 🔹 Serve Web UI with Chart.js for BPM Data
app.get('/', (req, res) => {
    const htmlContent = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Sensor Data</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f7f6; text-align: center; padding: 20px; }
            table { width: 80%; margin: 20px auto; border-collapse: collapse; background-color: white; }
            th, td { border: 1px solid #ddd; padding: 10px; text-align: center; }
            th { background-color: #4CAF50; color: white; }
            canvas { max-width: 800px; margin: 20px auto; display: block; }
        </style>
    </head>
    <body>

        <h1>📊 Sensor Data Dashboard</h1>

        <script>
            fetch('/error-status')
                .then(response => response.json())
                .then(status => {
                    if (status.intrusion) {
                        alert("⚠️ Intrusion Detected!");
                    }
                });

            fetch('/data')
                .then(response => response.json())
                .then(data => {
                    const tableBody = document.getElementById('table-body');
                    Object.keys(data).forEach(sensor => {
                        data[sensor].forEach(item => {
                            const row = document.createElement('tr');
                            row.innerHTML = \`
                                <td>\${sensor}</td>
                                <td>\${item.timestamp.split(' ')[0]}</td>
                                <td>\${item.timestamp.split(' ')[1]}</td>
                                <td>\${item.bpm}</td>
                            \`;
                            tableBody.appendChild(row);
                        });
                    });
                });

            const sensorDropdown = document.getElementById('sensor-dropdown');
            const sensorGraph = document.getElementById('sensorGraph');
            const chartCtx = sensorGraph.getContext('2d');
            let chart;

            sensorDropdown.addEventListener('change', (event) => {
                const sensorId = event.target.value;

                if (chart) {
                    chart.destroy();
                }

                if (sensorId === 'none') {
                    sensorGraph.style.display = 'none';
                } else {
                    fetch(\`/data/\${sensorId}\`)
                        .then(response => response.json())
                        .then(sensorData => {
                            const labels = sensorData.map(item => item.timestamp);
                            const bpmData = sensorData.map(item => item.bpm);
                            
                            sensorGraph.style.display = 'block';

                            chart = new Chart(chartCtx, {
                                type: 'line',
                                data: {
                                    labels: labels,
                                    datasets: [{
                                        label: 'BPM over Time',
                                        data: bpmData,
                                        borderColor: 'rgba(75, 192, 192, 1)',
                                        backgroundColor: 'rgba(75, 192, 192, 0.2)',
                                        fill: true
                                    }]
                                },
                                options: {
                                    scales: {
                                        x: { title: { display: true, text: 'Date & Time' } },
                                        y: { title: { display: true, text: 'BPM' } }
                                    }
                                }
                            });
                        });
                }
            });
        </script>

        <table>
            <thead>
                <tr>
                    <th>Sensor ID</th>
                    <th>Date</th>
                    <th>Time</th>
                    <th>BPM</th>
                </tr>
            </thead>
            <tbody id="table-body"></tbody>
        </table>

        <select id="sensor-dropdown">
            <option value="none">None</option>
            <option value="sensor1">Sensor 1</option>
            <option value="sensor2">Sensor 2</option>
        </select>

        <canvas id="sensorGraph"></canvas>

    </body>
    </html>
    `;

    res.send(htmlContent);
});

// 🔹 Get Intrusion Status
app.get('/error-status', (req, res) => {
    return res.status(200).json({ intrusion });
});

registerWithTRA();
app.listen(PORT, () => console.log(`Hospital server running on port ${PORT}`));
