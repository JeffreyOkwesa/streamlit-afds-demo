import streamlit as st
import re
from urllib.parse import urlparse
import requests

# Function to analyze email content and detect links
def analyze_email(email_text):
    urls = extract_urls(email_text)
    malicious_urls = []

    # Check if URLs are malicious
    for url in urls:
        if is_malicious(url):
            malicious_urls.append(url)
    
    return malicious_urls

# Function to extract URLs from email text
def extract_urls(text):
    # Extract URLs using a regular expression
    urls = re.findall(r'https?://[^\s]+', text)
    return urls

# Function to determine if a URL is malicious (simplified for this example)
def is_malicious(url):
    # Example: Check if the URL domain is known to be malicious or suspicious
    suspicious_domains = ['bit.ly', 'goo.gl', 'short.ly', 'example.com']
    parsed_url = urlparse(url)
    
    # Check if the domain of the URL is in the suspicious list
    if parsed_url.netloc in suspicious_domains:
        return True
    return False

# Function to check URL reputation via an external service (optional API integration)
def check_url_reputation(url):
    # In a real scenario, this could integrate an API like Google's Safe Browsing or PhishTank
    api_key = "YOUR_API_KEY_HERE"  # Replace with actual API key
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    
    # Here, you would send the URL for checking the reputation via an API
    response = requests.post(api_url, json={"client": {"clientId": "streamlit", "clientVersion": "1.0"}, "threatInfo": {"threatTypes": ["MALWARE", "PHISHING"], "platformTypes": ["ANY_PLATFORM"], "url": url}})
    
    return response.json()

# Function to neutralize harmful links by removing or warning
def neutralize_links(email_text, malicious_urls):
    for url in malicious_urls:
        email_text = email_text.replace(url, "[WARNING: Malicious Link Removed]")
    return email_text

# Function to perform email content analysis for phishing keywords
def analyze_email_content(email_text):
    phishing_keywords = ['urgent', 'verify account', 'click here', 'your account has been compromised', 'suspicious activity']
    suspicious_keywords = []

    # Check for phishing-related keywords
    for keyword in phishing_keywords:
        if keyword.lower() in email_text.lower():
            suspicious_keywords.append(keyword)
    
    return suspicious_keywords

# Streamlit UI
def main():
    # Apply Streamlit's Dark Theme
    st.set_page_config(page_title="AFDS DEMO - Phishing Email Detection", page_icon="🔍", layout="wide")
    
    # Custom CSS for the dark mode and other styling
    st.markdown(
        """
        <style>
        body {
            background-color: #121212;
            color: #e0e0e0;
        }
        .streamlit-expanderHeader {
            color: #e0e0e0;
        }
        .stButton>button {
            background-color: #6200ea;
            color: white;
            font-weight: bold;
        }
        .stButton>button:hover {
            background-color: #3700b3;
        }
        .stTextInput>div>div>input {
            background-color: #333333;
            color: white;
        }
        .stTextInput>div>div>input:focus {
            border: 2px solid #6200ea;
        }
        .stTextArea>div>div>textarea {
            background-color: #333333;
            color: white;
        }
        .stTextArea>div>div>textarea:focus {
            border: 2px solid #6200ea;
        }
        .stDownloadButton>button {
            background-color: #6200ea;
            color: white;
            font-weight: bold;
        }
        .stDownloadButton>button:hover {
            background-color: #3700b3;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    st.title("🔍 AFDS DEMO - Phishing Email Detection")

    st.write(
        """
        Welcome to the **AFDS email analysis tool**. Paste an email below, or upload a text file, to analyze it for harmful links and phishing-related keywords. 
        This app will neutralize suspicious URLs and flag potential phishing attempts.
        """
    )

    # Provide option to either paste email text or upload a file
    input_method = st.radio("Choose your input method", ("Paste email content", "Upload email text file"))

    email_text = ""

    if input_method == "Paste email content":
        email_text = st.text_area("Paste the email content here...", height=200, placeholder="Enter email content...")

    if input_method == "Upload email text file":
        uploaded_file = st.file_uploader("Upload your email text file", type="txt")
        if uploaded_file is not None:
            email_text = uploaded_file.getvalue().decode("utf-8")

    # Add a stylized button for analysis
    analyze_button = st.button("🔍 Analyze Email", help="Click to analyze the email for harmful links")

    if analyze_button:
        if email_text:
            # Display loading spinner while analyzing
            with st.spinner('Analyzing email...'):
                malicious_urls = analyze_email(email_text)
                suspicious_keywords = analyze_email_content(email_text)
                
                # Show detected malicious URLs
                if malicious_urls:
                    st.subheader("🚨 Suspicious Links Found:")
                    for url in malicious_urls:
                        st.write(f"- {url}")
                    st.warning("These links have been flagged as suspicious.")

                # Show suspicious email content based on keywords
                if suspicious_keywords:
                    st.subheader("⚠️ Potential Phishing Keywords Found:")
                    for keyword in suspicious_keywords:
                        st.write(f"- {keyword}")
                    st.warning("These phrases suggest a potential phishing attempt.")

                # Neutralize malicious links
                neutralized_email = neutralize_links(email_text, malicious_urls)

                st.subheader("✅ Neutralized Email Content:")
                st.text_area("Neutralized Email:", neutralized_email, height=200)

                # Option to download the neutralized email
                st.download_button(
                    label="Download Neutralized Email",
                    data=neutralized_email,
                    file_name="neutralized_email.txt",
                    mime="text/plain"
                )

            # Final message if no suspicious elements were detected
            if not malicious_urls and not suspicious_keywords:
                st.success("✅ No suspicious links or phishing indicators detected in the email.")

        else:
            st.warning("⚠️ Please enter the email content for analysis.")

# Run the Streamlit app
if __name__ == "__main__":
    main()
