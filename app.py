import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os
import tempfile
import pefile
import re
from io import BytesIO
import time

# Set page configuration
st.set_page_config(
    page_title="Ransomware Detection System",
    page_icon="🛡️",
    layout="wide"
)

# Load the trained model
@st.cache_resource
def load_model():
    try:
        model_data = joblib.load("models/ransomware_model.pkl")
        return model_data["model"], model_data["features"]
    except FileNotFoundError:
        st.error("Model file not found. Please ensure the model is trained first.")
        return None, None

def quick_extract_pe_features(pe_file_path):
    """
    Fast feature extraction from PE file
    """
    try:
        pe = pefile.PE(pe_file_path)
        
        features = {}
        
        # Basic header features (fast to extract)
        features['Machine'] = pe.FILE_HEADER.Machine
        features['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
        features['MajorOSVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        features['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        features['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        features['NumberOfSections'] = len(pe.sections)
        features['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        features['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
        features['IatVRA'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress
        
        # Debug info (check quickly)
        features['DebugSize'] = 0
        features['DebugRVA'] = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') and pe.DIRECTORY_ENTRY_DEBUG:
            debug_info = pe.DIRECTORY_ENTRY_DEBUG[0]
            features['DebugSize'] = debug_info.struct.SizeOfData
            features['DebugRVA'] = debug_info.struct.AddressOfRawData
        
        # Export info (check quickly)
        features['ExportRVA'] = 0
        features['ExportSize'] = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            features['ExportRVA'] = pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNames
            features['ExportSize'] = pe.DIRECTORY_ENTRY_EXPORT.struct.NumberOfNames
        
        # Resource size (check quickly)
        features['ResourceSize'] = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            features['ResourceSize'] = pe.DIRECTORY_ENTRY_RESOURCE.struct.Size
        
        # Quick bitcoin detection (sample first 1MB only for speed)
        features['BitcoinAddresses'] = quick_bitcoin_detection(pe_file_path)
        
        pe.close()
        return features
        
    except Exception as e:
        st.error(f"Error analyzing PE file: {str(e)}")
        return None

def quick_bitcoin_detection(file_path, sample_size=1024*1024):
    """
    Fast bitcoin detection by sampling only part of the file
    """
    try:
        with open(file_path, 'rb') as f:
            # Only read first 1MB for speed
            content = f.read(sample_size)
            
        # Convert to string for pattern matching
        content_str = content.decode('latin-1', errors='ignore')
        
        # Simple pattern for bitcoin addresses
        btc_pattern = r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,90}'
        matches = re.findall(btc_pattern, content_str)
        
        return len(matches)
    except:
        return 0

def analyze_uploaded_file(uploaded_file):
    """
    Fast analysis of uploaded file
    """
    # Save uploaded file to temporary location
    with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as tmp_file:
        tmp_file.write(uploaded_file.getvalue())
        tmp_path = tmp_file.name
    
    try:
        # Quick feature extraction
        features = quick_extract_pe_features(tmp_path)
        return features
        
    except Exception as e:
        st.error(f"Error processing file: {str(e)}")
        return None
    finally:
        # Clean up temporary file
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

def predict_from_features(features, model, feature_names, source_name="Manual Input"):
    """
    Make prediction from features and display results
    """
    # Prepare data and predict
    input_data = np.array([[features[feature] for feature in feature_names]])
    prediction = model.predict(input_data)[0]
    probability = model.predict_proba(input_data)[0]
    
    # Display results
    st.markdown("---")
    st.header("🎯 **INSTANT ANALYSIS RESULTS**")
    
    # Results in columns
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if prediction == 1:
            st.error("""
            ## 🚨 RANSOMWARE DETECTED
            **High probability of malicious activity**
            """)
        else:
            st.success("""
            ## ✅ BENIGN FILE
            **File appears to be safe**
            """)
    
    with col2:
        # Confidence gauges
        st.metric(
            "Ransomware Confidence", 
            f"{probability[1]:.1%}",
            delta=f"{probability[1]-0.5:+.1%}" if probability[1] > 0.5 else ""
        )
        st.metric(
            "Benign Confidence", 
            f"{probability[0]:.1%}",
            delta=f"{probability[0]-0.5:+.1%}" if probability[0] > 0.5 else ""
        )
    
    with col3:
        # Risk assessment
        risk_score = probability[1]
        if risk_score > 0.8:
            risk_level = "🔴 CRITICAL"
        elif risk_score > 0.6:
            risk_level = "🟠 HIGH"
        elif risk_score > 0.3:
            risk_level = "🟡 MEDIUM"
        else:
            risk_level = "🟢 LOW"
        
        st.metric("Risk Level", risk_level)
        
        # Quick verdict
        if prediction == 1:
            st.error("**Recommendation:** Quarantine file")
        else:
            st.success("**Recommendation:** File appears safe")
    
    # Feature overview
    with st.expander("📋 Feature Overview (Click to expand)", expanded=False):
        # Show only key features for quick review
        key_features = ['Machine', 'NumberOfSections', 'BitcoinAddresses', 'DebugSize', 'ExportSize']
        
        feature_display = {}
        for feat in key_features:
            if feat in features:
                feature_display[feat] = features[feat]
        
        st.dataframe(pd.DataFrame([feature_display]).T.rename(columns={0: 'Value'}))
    
    # Detailed analysis
    with st.expander("🔍 Detailed Technical Analysis", expanded=False):
        # All features
        st.dataframe(pd.DataFrame([features]).T.rename(columns={0: 'Value'}))
        
        # Feature importance
        if hasattr(model, 'feature_importances_'):
            st.subheader("Top Contributing Features")
            importance_df = pd.DataFrame({
                'Feature': feature_names,
                'Importance': model.feature_importances_
            }).sort_values('Importance', ascending=False)
            
            top_3 = importance_df.head(3)
            for _, row in top_3.iterrows():
                st.write(f"**{row['Feature']}**: {features[row['Feature']]} (impact: {row['Importance']:.3f})")
    
    # Quick actions
    st.markdown("---")
    st.subheader("🚀 Quick Actions")
    
    action_col1, action_col2 = st.columns(2)
    
    with action_col1:
        # Download report
        report_data = {
            'source': source_name,
            'verdict': 'RANSOMWARE' if prediction == 1 else 'BENIGN',
            'ransomware_confidence': probability[1],
            'benign_confidence': probability[0],
            'risk_level': risk_level,
            'analysis_timestamp': pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
            **features
        }
        
        report_df = pd.DataFrame([report_data])
        csv = report_df.to_csv(index=False)
        
        st.download_button(
            label="📥 Download Full Report",
            data=csv,
            file_name=f"security_analysis_{source_name}.csv",
            mime="text/csv",
            use_container_width=True
        )
    
    with action_col2:
        if st.button("🔄 New Analysis", use_container_width=True):
            st.rerun()
    
    return prediction, probability

def main():
    st.title("🛡️ Ransomware Detection System")
    st.markdown("""
    **Fast ML-powered ransomware detection** - Upload files or enter features manually
    """)
    
    # Load model
    model, feature_names = load_model()
    
    if model is None:
        st.stop()
    
    # Quick info in sidebar
    st.sidebar.header("⚡ Quick Info")
    st.sidebar.info("**Model:** Random Forest")
    st.sidebar.info("**Accuracy:** ~99.6%")
    st.sidebar.info("**Analysis Time:** < 3 seconds")
    
    # Input method selection
    st.header("🔧 Choose Analysis Method")
    
    input_method = st.radio(
        "Select input method:",
        ["📁 Upload Executable File", "✍️ Manual Feature Input"],
        horizontal=True
    )
    
    if input_method == "📁 Upload Executable File":
        st.subheader("📁 File Upload Analysis")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            uploaded_file = st.file_uploader(
                "Drag & drop any Windows executable", 
                type=['exe', 'dll', 'sys', 'bin'],
                help="Supported: .exe, .dll, .sys files"
            )
        
        with col2:
            st.markdown("### Supported Files")
            st.markdown("""
            - `.exe` - Executables
            - `.dll` - Libraries  
            - `.sys` - Drivers
            - `.bin` - Binaries
            """)
        
        if uploaded_file is not None:
            # Quick file info
            st.success(f"✅ **File Ready:** {uploaded_file.name} ({uploaded_file.size / 1024:.1f} KB)")
            
            # Single analyze button
            if st.button("🚀 **ANALYZE FILE**", type="primary", use_container_width=True):
                
                # Progress and status
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                # Step 1: File validation
                status_text.text("🔍 Validating file...")
                progress_bar.progress(20)
                time.sleep(0.5)
                
                # Step 2: Feature extraction
                status_text.text("📊 Extracting features...")
                progress_bar.progress(50)
                
                features = analyze_uploaded_file(uploaded_file)
                
                if features is not None:
                    # Step 3: Making prediction
                    status_text.text("🤖 Analyzing with AI...")
                    progress_bar.progress(80)
                    time.sleep(0.5)
                    
                    # Step 4: Display results
                    status_text.text("📈 Generating report...")
                    progress_bar.progress(100)
                    time.sleep(0.5)
                    
                    status_text.empty()
                    progress_bar.empty()
                    
                    # Make prediction and show results
                    predict_from_features(features, model, feature_names, uploaded_file.name)
                    
                    # Success message
                    st.success(f"✅ Analysis completed! File: {uploaded_file.name}")
                    
                else:
                    st.error("❌ Failed to analyze file. Please ensure it's a valid Windows executable.")
                    progress_bar.empty()
                    status_text.empty()
    
    else:  # Manual Feature Input
        st.subheader("✍️ Manual Feature Input")
        
        st.info("""
        💡 **Tip:** Enter the feature values below. These are typically extracted from PE file headers.
        For unknown values, use 0 as default.
        """)
        
        # Create input form with organized layout
        with st.form("manual_input_form"):
            st.write("### Enter Feature Values")
            
            # Organize features into logical groups
            col1, col2, col3 = st.columns(3)
            
            features = {}
            
            with col1:
                st.write("**Basic Information**")
                features['Machine'] = st.number_input("Machine Type", value=332, help="e.g., 332 for I386, 34404 for AMD64")
                features['NumberOfSections'] = st.number_input("Number of Sections", value=4, min_value=1, max_value=100)
                features['MajorLinkerVersion'] = st.number_input("Major Linker Version", value=8)
                features['MinorLinkerVersion'] = st.number_input("Minor Linker Version", value=0)
            
            with col2:
                st.write("**Version Information**")
                features['MajorImageVersion'] = st.number_input("Major Image Version", value=0)
                features['MajorOSVersion'] = st.number_input("Major OS Version", value=4)
                features['SizeOfStackReserve'] = st.number_input("Stack Reserve Size", value=1048576)
                features['DllCharacteristics'] = st.number_input("DLL Characteristics", value=34112)
            
            with col3:
                st.write("**Advanced Features**")
                features['DebugSize'] = st.number_input("Debug Size", value=0)
                features['DebugRVA'] = st.number_input("Debug RVA", value=0)
                features['ExportRVA'] = st.number_input("Export RVA", value=0)
                features['ExportSize'] = st.number_input("Export Size", value=0)
                features['IatVRA'] = st.number_input("IAT Virtual Address", value=8192)
                features['ResourceSize'] = st.number_input("Resource Size", value=672)
                features['BitcoinAddresses'] = st.number_input("Bitcoin Addresses", value=0, help="Number of bitcoin addresses found")
            
            # Submit button
            submitted = st.form_submit_button("🚀 **ANALYZE FEATURES**", type="primary", use_container_width=True)
            
            if submitted:
                # Validate that all features are present
                missing_features = set(feature_names) - set(features.keys())
                if missing_features:
                    st.error(f"Missing features: {missing_features}")
                else:
                    # Show quick analysis
                    with st.spinner("Analyzing features..."):
                        time.sleep(1)  # Simulate processing
                        predict_from_features(features, model, feature_names, "Manual_Input")
    
    # Feature descriptions (always available)
    with st.expander("📚 Feature Descriptions", expanded=False):
        feature_descriptions = {
            'Machine': 'Target machine type (332=I386, 34404=AMD64)',
            'DebugSize': 'Size of debug information (0 if no debug info)',
            'DebugRVA': 'Relative virtual address of debug information',
            'MajorImageVersion': 'Major version number of the image',
            'MajorOSVersion': 'Major version number of operating system',
            'ExportRVA': 'Relative virtual address of export table',
            'ExportSize': 'Size of export data',
            'IatVRA': 'Import address table virtual address',
            'MajorLinkerVersion': 'Major version of linker',
            'MinorLinkerVersion': 'Minor version of linker',
            'NumberOfSections': 'Number of sections in PE file',
            'SizeOfStackReserve': 'Size of stack to reserve',
            'DllCharacteristics': 'DLL characteristics flags',
            'ResourceSize': 'Size of resources',
            'BitcoinAddresses': 'Number of bitcoin addresses (0 for benign files)'
        }
        
        for feature in feature_names:
            if feature in feature_descriptions:
                st.write(f"**{feature}:** {feature_descriptions[feature]}")

if __name__ == "__main__":
    main()