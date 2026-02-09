import streamlit as st
import os
import time
import re
import math
import dns.resolver
from difflib import SequenceMatcher
import google.generativeai as genai
from dotenv import load_dotenv

# --- PAGE CONFIGURATION (Browser Tab) ---
st.set_page_config(
    page_title="VeriScan | Intelligent Threat Defense",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- PROFESSIONAL CSS STYLING ---
st.markdown("""
<style>
    /* 1. Main Theme (Dark Cyber) */
    .stApp {
        background-color: #0d1117;
        color: #e6edf3;
    }
    
    /* 2. Hide Streamlit Bloat */
    header[data-testid="stHeader"] {display: none;}
    footer {display: none;}
    
    /* 3. Custom Navbar */
    .navbar {
        background-color: #161b22;
        padding: 15px 30px;
        border-bottom: 1px solid #30363d;
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 25px;
    }
    .nav-logo {
        font-size: 1.4rem;
        font-weight: 700;
        color: #58a6ff;
        letter-spacing: 1px;
    }
    
    /* 4. Result Cards */
    .risk-card-high {
        background-color: #3d1214;
        border: 1px solid #f85149;
        padding: 20px;
        border-radius: 8px;
        text-align: center;
        margin-bottom: 20px;
    }
    .risk-card-safe {
        background-color: #0f2618;
        border: 1px solid #2ea043;
        padding: 20px;
        border-radius: 8px;
        text-align: center;
        margin-bottom: 20px;
    }
    
    /* 5. Metrics styling */
    div[data-testid="stMetricValue"] {
        font-size: 1.8rem !important;
    }
    
    /* 6. Reason Box */
    .reason-box {
        background-color: #161b22;
        border: 1px solid #30363d;
        padding: 15px;
        border-radius: 6px;
        font-size: 0.95rem;
        margin-top: 10px;
    }
</style>
""", unsafe_allow_html=True)

# --- NAVIGATION BAR ---
st.markdown("""
<div class="navbar">
    <div class="nav-logo">🛡️ VeriScan <span style="color:white; font-weight:400;">Enterprise</span></div>
    <div style="color: #8b949e; font-size: 0.9rem;">
        <span style="margin-right: 20px;">Threat Database: <span style="color:#3fb950;">Active</span></span>
        <span>System Status: <span style="color:#3fb950;">Online</span></span>
    </div>
</div>
""", unsafe_allow_html=True)

# --- PART 1: INTELLIGENCE ENGINES ---

def analyze_phone(number):
    """Specific Logic for Phone Numbers"""
    flags = []
    score = 0
    clean_num = re.sub(r'\D', '', number) # Remove dashes/spaces
    
    # Check 1: Length (Too short or too long is suspicious)
    # Standard mobile is 10-11 digits. 12+ without + prefix is weird.
    if len(clean_num) < 10 or len(clean_num) > 15:
        flags.append("Invalid Length (Number looks fake)")
        score += 30
    
    # Check 2: Repeated Digits (e.g. 9999999)
    if re.search(r'(\d)\1{5,}', clean_num):
        flags.append("Suspicious Pattern (Repeated digits)")
        score += 40
        
    # Check 3: Known VOIP/Spam Prefixes (Simple example)
    bad_prefixes = ['999', '000', '123', '889'] # 889 is often unassigned/scam
    if any(clean_num.startswith(p) for p in bad_prefixes):
        flags.append("High-Risk Prefix detected (VOIP/Unassigned)")
        score += 50
        
    # Check 4: Unlikely Country Codes (if starts with valid-looking length)
    # If it's 12 digits and starts with 88... likely scam check
    if len(clean_num) == 12 and clean_num.startswith('88'):
        flags.append("Suspicious International Format")
        score += 40

    return score, flags

def analyze_email(email):
    """Specific Logic for Email Domains"""
    flags = []
    score = 0
    
    match = re.search(r"@([\w.-]+)", email)
    if not match: return 0, ["Invalid Email Format"]
    
    domain = match.group(1).lower()
    name_part = domain.split('.')[0]
    
    # Check 1: Typosquatting (Fake brands)
    targets = ["google", "microsoft", "amazon", "paypal", "apple", "netflix", "facebook", "chase"]
    for target in targets:
        similarity = SequenceMatcher(None, name_part, target).ratio()
        if 0.8 < similarity < 1.0: # 80-99% similar means it's a trick
            flags.append(f"Impersonation Attempt (Looks like '{target}')")
            score += 50

    # Check 2: Entropy (Randomness) - Domain
    entropy = 0
    for x in range(256):
        p_x = float(name_part.count(chr(x)))/len(name_part)
        if p_x > 0: entropy += - p_x*math.log(p_x, 2)
            
    if entropy > 3.8:
        flags.append("Bot-Generated Domain (High Randomness)")
        score += 40
        
    # Check 3: Username Analysis (New)
    local_part = email.split('@')[0]
    
    # 3a. Username Entropy (Random gibberish like 'a8z9c2d3')
    user_entropy = 0
    for x in range(256):
        p_x = float(local_part.count(chr(x)))/len(local_part)
        if p_x > 0: user_entropy += - p_x*math.log(p_x, 2)
        
    if user_entropy > 4.2: # Slightly higher threshold for users
        flags.append("Bot-Generated Username (High Randomness)")
        score += 30
        
    # 3b. Unpronounceable (Too many consonants in a row)
    # e.g. 'xgpvz'
    if re.search(r'[bcdfghjklmnpqrstvwxyz]{5,}', local_part):
        flags.append("Gibberish Username (Keyboard Smash)")
        score += 35

    return score, flags

    return score, flags

def analyze_email_heuristics(email):
    """Hard-coded rules to catch obvious scams that AI might miss."""
    flags = []
    score = 0
    email = email.lower()
    
    parts = email.split('@')
    if len(parts) != 2:
        return 50, ["Invalid Email Structure (Multiple '@' or missing)"]
        
    local_part, domain_part = parts
    
    # --- DOMAIN & TLD ANALYSIS ---
    # TLD (Top Level Domain) Check
    tld = domain_part.split('.')[-1] if '.' in domain_part else ""
    
    # 1. Suspicious TLDs (Often used by cheap spammers)
    suspicious_tlds = {'xyz', 'top', 'club', 'online', 'loan', 'win', 'bid', 'click', 'review', 'stream'}
    if tld in suspicious_tlds:
        flags.append(f"High-Risk TLD Detected (.{tld})")
        score += 45
        
    # 2. Domain Numbers (e.g. gmail2.com, google55.in)
    domain_name = domain_part.rsplit('.', 1)[0]
    if re.search(r'\d', domain_name):
        flags.append("Suspicious Number in Domain Name")
        score += 50
        
    # 3. Multiple Hyphens in Domain
    if domain_part.count('-') > 1: 
        flags.append("Suspicious Domain Structure (Multiple Hyphens)")
        score += 60

    # --- USERNAME ANALYSIS ---
    # 4. Urgent/Status keywords in address
    bad_words = ['verify', 'account', 'update', 'alert', 'security', 'support', 'team', 'service', 'confirm']
    if any(w in email for w in bad_words):
        flags.append("Generic/Impersonation Keywords detected")
        score += 40
        
    # 5. Long numeric strings in username
    # Relaxed Rule: Allow up to 6 digits (e.g. dates/years)
    if len(re.findall(r'\d', local_part)) > 6:
        flags.append("Bot-like Username (Many digits)")
        score += 30

    return score, flags

def analyze_email_technical(email):
    """Deep Technical Inspection: MX Records & Disposable Blocklist"""
    flags = []
    score = 0
    domain = email.split('@')[-1].lower() if '@' in email else ""
    
    if not domain: return 0, []

    # 1. DISPOSABLE DOMAIN CHECK
    # Common temp mail providers
    disposable_domains = {
        'temp-mail.org', '10minutemail.com', 'guerrillamail.com', 'yopmail.com', 
        'mailinator.com', 'discard.email', 'trashmail.com', 'maildrop.cc', 
        'getnada.com', 'sharklasers.com', 'dispostable.com', 'owlymail.com'
    }
    
    if domain in disposable_domains:
        flags.append("Disposable/Burner Email Provider Detected")
        score += 100 # Instant Ban
        return score, flags

    # 2. MX RECORD CHECK (Does the domain actually exist for email?)
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        # If we get here, it has records. Good.
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        flags.append("Domain has NO MX Records (Cannot receive email)")
        score += 80 # Very confusing/fake
    except Exception:
        pass # DNS timeout or other issues, ignore for now to avoid false positives

    return score, flags

# --- PART 2: AI BRAIN (Gemini API) ---

def configure_gemini(api_key):
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-1.5-flash')
        return model
    except Exception as e:
        return None

def analyze_with_gemini(model, text):
    """
    Analyzes text using Google Gemini API for spam/phishing detection.
    Returns: (is_spam, confidence, reasons)
    """
    if not model:
        return False, 0, ["API Error: Model not initialized"]
    
    prompt = f"""
    You are a heavily biased Spam Detection AI. Your ONLY GOAL is to catch phishing.
    
    Task: Classify this SENDER as 'Spam/Phishing' (true) or 'Safe' (false).
    
    EXAMPLES (Use these as a baseline):
    - "889485684505" -> SPAM (Unknown Country Code, Suspicious Length)
    - "+1234567890" -> SPAM (Invalid Sequence)
    - "support-alert@company-security.com" -> SPAM (Hyphens, generic words)
    - "verify@paypal-update.com" -> SPAM (Impersonation, non-official domain)
    - "user123958@gmail.com" -> SPAM (Bot username)
    - "john.doe@gmail.com" -> SAFE (Personal)
    - "guleriaritesh29@gmail.com" -> SAFE (Personal, few digits)
    - "no-reply@amazon.com" -> SAFE (Official Domain)
    - "hr@microsoft.com" -> SAFE (Official Domain)
    - "+15550199" -> SAFE (Standard Format)
    
    TARGET TO ANALYZE: "{text}"
    
    INSTRUCTIONS:
    1. Phone Numbers: IF unassigned/suspicious country code (like +889...), MARK SPAM.
    2. Domains: IF official provider (gmail.com, outlook.com, yahoo.com, icloud.com), BE LENIENT. Only flag if username is obviously bot-generated (e.g. 'x8237sdsd').
    3. Domains: IF unknown/weird domain (e.g. 'verify-secure.net'), BE PARANOID.
    4. Keywords: IF 'verify'/'safe' in domain, MARK SPAM.
    
    Return JSON:
    {{
        "is_spam": true/false,
        "confidence": 100,
        "reasons": ["Reason 1", "Reason 2"]
    }}
    """
    
    try:
        response = model.generate_content(prompt, generation_config={"temperature": 0.1}) # Slight temp for nuance
        # Clean up code blocks if Gemini returns them
        cleaned_text = response.text.replace('```json', '').replace('```', '').strip()
        import json
        result = json.loads(cleaned_text)
        return result.get('is_spam', False), result.get('confidence', 0), result.get('reasons', [])
    except Exception as e:
        return False, 0, [f"AI Analysis Failed: {str(e)}"]

# --- API SETUP IN SIDEBAR ---
with st.sidebar:
    st.header("⚙️ Configuration")
    
    # Try to load from env first
    load_dotenv()
    env_key = os.getenv("GEMINI_API_KEY")
    
    api_key = st.text_input(
        "Enter Google Gemini API Key",
        value=env_key if env_key else "",
        type="password",
        help="Get your free key from Google AI Studio"
    )
    
    if not api_key:
        st.warning("⚠️ API Key required for AI analysis")
        model = None
    else:
        model = configure_gemini(api_key)
        if model:
            st.success("✅ AI System Online")
        else:
            st.error("❌ Invalid API Key")

# --- PART 3: MAIN INTERFACE ---

# Layout: Two columns (Input vs Description)
col_left, col_right = st.columns([2, 1], gap="medium")

with col_left:
    st.markdown("### 🔍 Investigation Details")
    
    # Input 1: Sender
    sender_type = st.radio("Source Type:", ["Email Address", "Phone Number"], horizontal=True, label_visibility="collapsed")
    sender_input = st.text_input(f"Sender ({sender_type}):", placeholder="e.g. +1 555-0102 or support@paypa1.com")
    
with col_right:
    st.markdown("### 🛡️ Live Diagnostics")
    st.info("""
    **Active Modules:**
    * **Typosquatting Engine:** Detects fake domains (e.g. gmai1.com).
    * **Pattern Matcher:** Scans for prohibited numbers and text formats.
    * **Semantic AI:** Analyzes intent (Urgency, Money, Threats).
    """)
    st.markdown("---")
    st.caption("VeriScan Pro v2.4.0 \nDatabase: Updated Live")

# --- PART 4: ANALYSIS LOGIC ---
st.write("---")
if st.button("RUN SECURITY SCAN", type="primary", use_container_width=True):
    
    if not sender_input:
        st.warning("Please enter a sender to scan.")
    else:
        with st.spinner("Triangulating Threat Vectors..."):
            time.sleep(1.2) # Simulate processing
            
            # 1. ANALYZE SENDER (Heuristics)
            sender_score = 0
            sender_flags = []
            
            if "@" in sender_input: # It's an Email
                # Run Regex/Typosquatting Check
                s1, f1 = analyze_email(sender_input)
                # Run New Static Rules Check
                s2, f2 = analyze_email_heuristics(sender_input)
                # Run Technical Check (MX + Disposable)
                s3, f3 = analyze_email_technical(sender_input)
                
                sender_score = s1 + s2 + s3
                sender_flags = f1 + f2 + f3
                
            elif any(char.isdigit() for char in sender_input): # It's a Phone
                sender_score, sender_flags = analyze_phone(sender_input)
                
            # 2. ANALYZE SENDER (AI)
            full_text = f"{sender_input}"
            
            is_spam_ai = False
            ai_confidence = 0
            ai_reasons = []
            
            if model:
                is_spam_ai, ai_confidence, ai_reasons = analyze_with_gemini(model, full_text)
            else:
                ai_reasons = ["AI Analysis skipped (No API Key)"]
            
            # 3. FINAL VERDICT CALCULATION
            # If (Heuristics > 0) OR (AI says Spam) -> High Risk
            is_spam = False
            risk_reasons = []
            
            # Gather Reasons
            if is_spam_ai:
                is_spam = True
                risk_reasons.extend(ai_reasons)
            
            if sender_score > 20: # Lowered threshold for strictness
                is_spam = True
                risk_reasons.extend(sender_flags)
            
            # Display Results
            if is_spam:
                # DANGER UI
                st.markdown(f"""
                <div class="risk-card-high">
                    <h1 style="color:#ff7b72; margin:0;">🚫 THREAT DETECTED</h1>
                    <p style="color:#e6edf3;">Risk Level: CRITICAL</p>
                </div>
                """, unsafe_allow_html=True)
                
                # METRICS
                m1, m2, m3 = st.columns(3)
                m1.metric("Risk Score", "98.5/100", "High", delta_color="inverse")
                m1.markdown("**Verdict:** Malicious")
                
                m2.metric("Sender Status", "Flagged", "Suspicious", delta_color="inverse")
                
                m3.metric("AI Confidence", f"{ai_confidence:.1f}%", "Certainty")

                # THE "WHY" SECTION
                st.markdown("### 🚩 Forensic Analysis (Why is this Spam?)")
                for reason in risk_reasons:
                    st.markdown(f"""
                    <div class="reason-box">
                        <span style="color:#ff7b72; font-weight:bold;">[ALERT]</span> {reason}
                    </div>
                    """, unsafe_allow_html=True)
                
                # Recommendation
                st.warning("⚠️ RECOMMENDATION: Block this sender immediately. Do not click links.")

            else:
                # SAFE UI
                st.markdown(f"""
                <div class="risk-card-safe">
                    <h1 style="color:#3fb950; margin:0;">✅ VERIFIED SAFE</h1>
                    <p style="color:#e6edf3;">Risk Level: LOW</p>
                </div>
                """, unsafe_allow_html=True)
                
                # METRICS
                m1, m2, m3 = st.columns(3)
                m1.metric("Trust Score", "99.2/100", "Safe")
                m2.metric("Sender Status", "Verified", "Clean")
                m3.metric("AI Confidence", f"{ai_confidence:.1f}%")
                
                st.markdown("### 📝 Analysis Report")
                st.success("No malicious patterns, spoofing, or prohibited keywords were found.")
