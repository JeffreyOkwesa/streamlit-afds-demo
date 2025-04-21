import streamlit as st

st.title("My First Streamlit App")
st.write("Hello, world! This is my first Streamlit app.")
import streamlit as st
import re
from urllib.parse import urlparse

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

# Function to neutralize harmful links by removing or warning
def neutralize_links(email_text, malicious_urls):
    for url in malicious_urls:
        email_text = email_text.replace(url, "[WARNING: Malicious Link Removed]")
    return email_text

# Streamlit UI
def main():
    st.title("AFDS DEMO")

    st.write(
        "Welcome to the AFDS email analysis tool. Paste an email below, or upload a text file, to analyze it for harmful links. The app will neutralize suspicious URLs by warning or removing them."
    )

    # Provide option to either paste email text or upload a file
    input_method = st.radio("Choose your input method", ("Paste email content", "Upload email text file"))

    email_text = ""

    if input_method == "Paste email content":
        email_text = st.text_area("Paste the email content here...", height=200, placeholder="Enter email content...")

    if input_method == "Upload email text file":
        uploaded_file = st.file_uploader("Upload your email text file", type="txt")
        if uploaded_file is not None:
            email_text = uploaded_file.getvalue().decode("utf-8")  # This change should help handle the file content properly.

    # Button to trigger analysis
    if st.button("Analyze Email", key="analyze", help="Click to analyze the email for harmful links"):
        if email_text:
            # Analyze the email for harmful links
            malicious_urls = analyze_email(email_text)
            
            # Show URLs detected as malicious
            if malicious_urls:
                st.subheader("Suspicious Links Found:")
                for url in malicious_urls:
                    st.write(f"- {url}")
                
                # Neutralize links in the email content
                neutralized_email = neutralize_links(email_text, malicious_urls)
                st.subheader("Neutralized Email Content:")
                st.text_area("Neutralized Email:", neutralized_email, height=200)

                # Option to download the neutralized email
                st.download_button(
                    label="Download Neutralized Email",
                    data=neutralized_email,
                    file_name="neutralized_email.txt",
                    mime="text/plain"
                )
            else:
                st.success("No suspicious links detected in the email.")
        else:
            st.warning("Please enter the email content for analysis.")

if __name__ == "__main__":
    main()
