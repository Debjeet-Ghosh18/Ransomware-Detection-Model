import streamlit as st
import pandas as pd
import joblib

# Load trained model
model = joblib.load("ransomware_model.pkl")

st.set_page_config(page_title="🛡️ Ransomware Detection App", page_icon="🧠", layout="centered")

# Title
st.title("🛡️ Ransomware Detection App")
st.write("This app uses a Machine Learning model to detect whether a given file is **benign or ransomware** based on extracted static features.")

# Sidebar - mode selection
option = st.sidebar.selectbox("Choose input method:", ["Upload CSV", "Manual Input"])

# --- Upload Mode ---
if option == "Upload CSV":
    uploaded_file = st.file_uploader("Upload a CSV file with the same feature columns as your training data", type=["csv"])
    if uploaded_file is not None:
        data = pd.read_csv(uploaded_file)
        st.write("✅ File Uploaded Successfully!")
        st.dataframe(data.head())

        # Make predictions
        preds = model.predict(data)
        probs = model.predict_proba(data)[:, 1]

        # Combine results
        data['Prediction'] = ["Benign" if p == 1 else "Ransomware" for p in preds]
        data['Confidence'] = probs.round(2)

        st.write("### 🧾 Prediction Results:")
        st.dataframe(data)

# --- Manual Input Mode ---
else:
    st.write("Enter the feature values manually below:")

    # Example features based on your dataset
    Machine = st.number_input("Machine", 0)
    DebugSize = st.number_input("DebugSize", 0)
    DebugRVA = st.number_input("DebugRVA", 0)
    MajorImageVersion = st.number_input("MajorImageVersion", 0)
    MajorOSVersion = st.number_input("MajorOSVersion", 0)
    ExportRVA = st.number_input("ExportRVA", 0)
    ExportSize = st.number_input("ExportSize", 0)
    IatVRA = st.number_input("IatVRA", 0)
    NumberOfSections = st.number_input("NumberOfSections", 0)

    # Make dataframe from user input
    input_data = pd.DataFrame([[Machine, DebugSize, DebugRVA, MajorImageVersion,
                                MajorOSVersion, ExportRVA, ExportSize, IatVRA,
                                NumberOfSections]],
                              columns=['Machine', 'DebugSize', 'DebugRVA', 'MajorImageVersion',
                                       'MajorOSVersion', 'ExportRVA', 'ExportSize', 'IatVRA',
                                       'NumberOfSections'])

    if st.button("🔍 Predict"):
        pred = model.predict(input_data)[0]
        prob = model.predict_proba(input_data)[0][1]

        result = "✅ Benign" if pred == 1 else "🚨 Ransomware"
        st.markdown(f"### Result: {result}")
        st.write(f"**Confidence:** {prob:.2f}")

# Footer
st.markdown("---")
st.caption("Developed by [Your Name] | Machine Learning Ransomware Detector")
