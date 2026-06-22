# Horizon: Real-Time Log Orchestration Pipeline

If you have ever spent hours tailing multiple server logs trying to hunt down a single `OutOfMemoryError` or a brute-force SSH attempt, you know exactly why I built Horizon. 

Horizon is a lightweight, full-stack observability pipeline designed to catch, classify, and stream system logs to a centralized dashboard in absolute real-time. No manual refreshing and no SSH-ing into five different remote nodes—just instant, centralized visibility.


## Under the Hood

I designed the architecture to be robust but strictly decoupled. The core engine is built on Java 21 and Spring Boot (v3.3.0), which catches incoming network payloads and instantly broadcasts them out using an HTML5 Server-Sent Events (SSE) protocol. 

On the client side, I built a purely reactive UI using React.js and Vite. The dashboard catches the SSE stream and visually categorizes threats on the fly without ever needing a manual browser refresh. Because the ingestion layer accepts standard HTTP POST requests, any external server, background daemon, or basic shell script can easily push logs directly into the pipeline.


## Spin It Up Locally

To test this environment yourself, you will need Java 21+, Node.js, and a Linux environment (WSL on Windows works perfectly) to run the simulated ingestion scripts.

### 1. Boot the Backend Engine
Open a terminal, navigate into the backend directory, and let Maven compile and spin up the server:
```bash
cd backend-engine
mvn spring-boot:run
