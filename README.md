# VeriScan - Intelligent Spam & Phishing Detector

VeriScan is a next-generation spam filter that uses a **Hybrid Detection System** combining hard-coded heuristics with the advanced AI capabilities of **Google Gemini**.

It is designed to detect:
*   **Phishing Emails** (e.g. `support-alert@company-security.com`)
*   **Fake Phone Numbers** (e.g. unassigned country codes like `+889...`)
*   **Bot Usernames** (e.g. `a8z7c2d3@gmail.com`)
*   **Malicious Patterns** (Typosquatting, Urgent Keywords, Disposable Domains)

## Features

*   **Dual-Engine Analysis**:
    *   **Python Heuristics**: Instantly flags technically invalid or suspicious patterns (MX records, disposable domains, gibberish usernames).
    *   **AI Brain (Gemini)**: Analyzes the context and intent of the sender using a strict, "paranoid" prompt.
*   **Real-Time Verification**: Use `dnspython` to check if a domain actually exists and can receive email.
*   **Smart Whitelisting**: Recognizes legitimate providers (Gmail, Outlook) while still banning suspicious usernames on them.

## Setup

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/VeriScan.git
    cd VeriScan
    ```

2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configure API Key**:
    *   Get a free API Key from [Google AI Studio](https://aistudio.google.com/app/apikey).
    *   Create a `.env` file in the root directory.
    *   Add your key:
        ```env
        GEMINI_API_KEY=your_api_key_here
        ```

4.  **Run the App**:
    ```bash
    streamlit run app.py
    ```

## Technology Stack

*   **Frontend**: Streamlit
*   **AI Engine**: Google Gemini Pro/Flash
*   **DNS Tools**: `dnspython`
*   **Language**: Python 3.10+
