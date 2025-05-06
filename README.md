# FortiSIEM–TheHive Integration

This project integrates **Fortinet FortiSIEM** with **TheHive** using a Python script. It pulls high-severity events from FortiSIEM via its API and sends them as alerts to TheHive for further triage, investigation, and case management.

---

## 📁 Project Structure

```
fortisiem-thehive-integration/
├── .env                 # Environment variables (do NOT commit to Git)
├── main.py              # Main Python script for integration
├── requirements.txt     # Python dependencies
└── README.md            # Project documentation
```

---

## 🔧 Features

- Authenticates with FortiSIEM 7.3.1 using REST API
- Pulls recent high-severity events (severity > 3)
- Converts each event to a structured alert
- Sends alert to TheHive using its REST API
- Logs progress, errors, and deduplication attempts

---

## ✅ Requirements

- Python 3.7+
- Access to:
  - FortiSIEM API (`/phoenix/rest`)
  - TheHive API (`/api/alert`)

---

## 📦 Setup

### 1. Clone this repository

```bash
git clone https://github.com/your-username/fortisiem-thehive-integration.git
cd fortisiem-thehive-integration
```

### 2. Create and configure `.env`

Create a `.env` file in the root directory:

```env
# FortiSIEM configuration
FSIEM_URL=https://your-fortisiem-url
FSIEM_USERNAME=your-fortisiem-username
FSIEM_PASSWORD=your-fortisiem-password

# TheHive configuration
THEHIVE_URL=http://your-thehive-url:9000
THEHIVE_API_KEY=your-thehive-api-key
```

> **Important:** Do not commit this file to version control.

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ Running the Script

```bash
python main.py
```

If successful, the script will:
- Log in to FortiSIEM
- Fetch high-severity events from the last 10 minutes
- Create alerts
- Send them to TheHive

---

## ⏲️ Optional: Schedule with Cron

To automate the script every 10 minutes:

```bash
crontab -e
```

Add:

```bash
*/10 * * * * /usr/bin/python3 /path/to/fortisiem-thehive-integration/main.py >> /var/log/fortisiem2hive.log 2>&1
```

---

## 🔐 Security Best Practices

- Use API users with minimal permissions.
- Restrict access to `.env`:
  
  ```bash
  chmod 600 .env
  ```

- Run inside a secured, monitored environment (internal VM or Docker container).

---

## 🚀 Roadmap (Suggestions)

- Add support for deduplication with alert caching
- Send observables as proper TheHive artifacts
- Dockerize the integration
- Add webhook support to handle real-time event forwarding

---

## 📚 References

- [FortiSIEM API Docs (7.3.1)](https://docs.fortinet.com/document/fortisiem)
- [TheHive Technical Documentation](https://docs.strangebee.com)
- [TheHive API Reference](https://docs.strangebee.com/thehive/api/overview/)

---

## 🛠️ Support

For issues, please open a GitHub issue or contact the maintainer.

---

## 📝 License

MIT License – see `LICENSE` file.
