import streamlit as st
import pandas as pd
import numpy as np
import joblib
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path

# Page configuration
st.set_page_config(
    page_title="Ransomware Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
    <style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        text-align: center;
        color: #1f77b4;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 15px;
        color: white;
        box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        text-align: center;
    }
    .metric-card h3 {
        color: white !important;
        font-size: 1rem;
        margin-bottom: 0.5rem;
        opacity: 0.9;
    }
    .metric-card h2 {
        color: white !important;
        font-size: 2.5rem;
        margin: 1rem 0;
        font-weight: bold;
    }
    .metric-card p {
        color: white !important;
        font-size: 0.9rem;
        opacity: 0.9;
    }
    .benign {
        color: #2ecc71;
        font-weight: bold;
    }
    .malicious {
        color: #e74c3c;
        font-weight: bold;
    }
    </style>
""", unsafe_allow_html=True)

# Load model
@st.cache_resource
def load_model():
    try:
        model_path = Path("models/ransomware_model.pkl")
        model_data = joblib.load(model_path)
        return model_data["model"], model_data["features"]
    except Exception as e:
        st.error(f"Error loading model: {e}")
        return None, None

# Main app
def main():
    # Header
    st.markdown('<h1 class="main-header">🛡️ Ransomware Detection System</h1>', unsafe_allow_html=True)
    st.markdown("---")
    
    # Load model
    model, feature_names = load_model()
    
    if model is None:
        st.error("⚠️ Failed to load the model. Please ensure the model file exists in the 'models' folder.")
        return
    
    # Sidebar
    with st.sidebar:
        st.image("https://img.icons8.com/color/96/000000/security-checked.png", width=100)
        st.title("Navigation")
        page = st.radio("", ["🏠 Home", "📊 Batch Analysis", "🔍 Single File Check", "📈 Model Info"])
        
        st.markdown("---")
        st.markdown("### About")
        st.info("This system uses machine learning to detect ransomware based on PE file characteristics.")
        
        st.markdown("### Features Used")
        with st.expander("View All Features"):
            for i, feat in enumerate(feature_names, 1):
                st.text(f"{i}. {feat}")
    
    # Pages
    if page == "🏠 Home":
        show_home_page(model, feature_names)
    elif page == "📊 Batch Analysis":
        show_batch_analysis_page(model, feature_names)
    elif page == "🔍 Single File Check":
        show_single_check_page(model, feature_names)
    else:
        show_model_info_page(model, feature_names)

def show_home_page(model, feature_names):
    st.header("Welcome to the Ransomware Detection System")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class="metric-card">
            <h3>🎯 Accuracy</h3>
            <h2>99.65%</h2>
            <p>Model accuracy on test data</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="metric-card">
            <h3>🌲 Algorithm</h3>
            <h2>Random Forest</h2>
            <p>200 trees, max depth 20</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="metric-card">
            <h3>📊 Features</h3>
            <h2>15</h2>
            <p>PE file characteristics</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    st.subheader("How It Works")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        #### 📤 Upload
        Upload a CSV file containing PE file features or enter values manually.
        
        #### 🔬 Analysis
        Our Random Forest model analyzes 15 key characteristics of the file.
        
        #### 📋 Results
        Get instant predictions with confidence scores and detailed explanations.
        """)
    
    with col2:
        st.info("""
        **Key Features Analyzed:**
        - Machine type
        - Debug information
        - Version details
        - Export/Import tables
        - Section information
        - DLL characteristics
        - Resource size
        - Bitcoin addresses (indicator)
        """)

def show_batch_analysis_page(model, feature_names):
    st.header("📊 Batch Analysis")
    st.write("Upload a CSV file containing multiple files to analyze")
    
    uploaded_file = st.file_uploader("Choose a CSV file", type="csv")
    
    if uploaded_file is not None:
        try:
            # Read the uploaded file
            df = pd.read_csv(uploaded_file)
            
            st.success(f"✅ File uploaded successfully! Found {len(df)} records.")
            
            # Show preview
            with st.expander("📄 Preview Data"):
                st.dataframe(df.head(10))
            
            # Check if required columns exist
            missing_cols = set(feature_names) - set(df.columns)
            if missing_cols:
                st.error(f"❌ Missing required columns: {missing_cols}")
                st.info("💡 **Tip**: Your CSV should contain these exact column names (case-sensitive):")
                st.code(", ".join(feature_names))
                
                # Show what columns were found
                st.warning(f"**Found columns in your file**: {', '.join(df.columns.tolist())}")
                return
            
            # Prepare data - only use the feature columns
            X = df[feature_names]
            
            # Keep original data for display (with FileName if present)
            display_cols = ['FileName'] if 'FileName' in df.columns else []
            
            if st.button("🚀 Run Analysis", type="primary"):
                with st.spinner("Analyzing files..."):
                    # Make predictions
                    predictions = model.predict(X)
                    probabilities = model.predict_proba(X)[:, 1]
                    
                    # Add results to dataframe
                    results_df = df.copy()
                    results_df['Prediction'] = ['Benign' if p == 1 else 'Ransomware' for p in predictions]
                    results_df['Confidence'] = probabilities
                    results_df['Risk_Level'] = pd.cut(
                        probabilities, 
                        bins=[0, 0.3, 0.7, 1.0], 
                        labels=['Low', 'Medium', 'High']
                    )
                    
                    # Reorder columns to show important info first
                    priority_cols = ['FileName', 'Prediction', 'Confidence', 'Risk_Level']
                    available_priority = [col for col in priority_cols if col in results_df.columns]
                    other_cols = [col for col in results_df.columns if col not in priority_cols]
                    results_df = results_df[available_priority + other_cols]
                    
                    # Display summary
                    col1, col2, col3, col4 = st.columns(4)
                    
                    benign_count = sum(predictions == 1)
                    malicious_count = sum(predictions == 0)
                    
                    with col1:
                        st.metric("Total Files", len(predictions))
                    with col2:
                        st.metric("Benign", benign_count, delta="Safe", delta_color="normal")
                    with col3:
                        st.metric("Ransomware", malicious_count, delta="Threat", delta_color="inverse")
                    with col4:
                        st.metric("Detection Rate", f"{(malicious_count/len(predictions)*100):.1f}%")
                    
                    # Visualization
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        # Pie chart
                        fig = px.pie(
                            names=['Benign', 'Ransomware'],
                            values=[benign_count, malicious_count],
                            title="Detection Results",
                            color_discrete_sequence=['#2ecc71', '#e74c3c']
                        )
                        st.plotly_chart(fig, use_container_width=True)
                    
                    with col2:
                        # Confidence distribution
                        fig = px.histogram(
                            probabilities,
                            nbins=20,
                            title="Confidence Score Distribution",
                            labels={'value': 'Confidence Score', 'count': 'Count'}
                        )
                        st.plotly_chart(fig, use_container_width=True)
                    
                    # Detailed results
                    st.subheader("📋 Detailed Results")
                    
                    # Filter options
                    filter_option = st.selectbox(
                        "Filter by:",
                        ["All", "Benign Only", "Ransomware Only", "High Risk"]
                    )
                    
                    if filter_option == "Benign Only":
                        display_df = results_df[results_df['Prediction'] == 'Benign']
                    elif filter_option == "Ransomware Only":
                        display_df = results_df[results_df['Prediction'] == 'Ransomware']
                    elif filter_option == "High Risk":
                        display_df = results_df[results_df['Risk_Level'] == 'High']
                    else:
                        display_df = results_df
                    
                    st.dataframe(
                        display_df.style.applymap(
                            lambda x: 'background-color: #d4edda' if x == 'Benign' else 'background-color: #f8d7da' if x == 'Ransomware' else '',
                            subset=['Prediction']
                        ),
                        use_container_width=True
                    )
                    
                    # Download results
                    csv = results_df.to_csv(index=False)
                    st.download_button(
                        label="📥 Download Results",
                        data=csv,
                        file_name="ransomware_detection_results.csv",
                        mime="text/csv"
                    )
        
        except Exception as e:
            st.error(f"❌ Error processing file: {e}")

def show_single_check_page(model, feature_names):
    st.header("🔍 Single File Check")
    st.write("Enter the file characteristics manually for analysis")
    
    # Create input form
    with st.form("single_check_form"):
        st.subheader("File Characteristics")
        
        col1, col2 = st.columns(2)
        
        input_data = {}
        
        for i, feature in enumerate(feature_names):
            with col1 if i % 2 == 0 else col2:
                input_data[feature] = st.number_input(
                    feature,
                    value=0,
                    help=f"Enter value for {feature}"
                )
        
        submitted = st.form_submit_button("🔍 Analyze File", type="primary")
        
        if submitted:
            # Create DataFrame
            input_df = pd.DataFrame([input_data])
            
            # Make prediction
            prediction = model.predict(input_df)[0]
            probability = model.predict_proba(input_df)[0][1]
            
            # Display result
            st.markdown("---")
            st.subheader("Analysis Result")
            
            col1, col2, col3 = st.columns(3)
            
            result_text = "Benign" if prediction == 1 else "Ransomware"
            result_color = "benign" if prediction == 1 else "malicious"
            risk_level = "Low" if probability > 0.7 else "Medium" if probability > 0.3 else "High"
            
            with col1:
                st.markdown(f'<h2 class="{result_color}">🔍 {result_text}</h2>', unsafe_allow_html=True)
            
            with col2:
                st.metric("Confidence Score", f"{probability*100:.2f}%")
            
            with col3:
                st.metric("Risk Level", risk_level)
            
            # Feature importance for this prediction
            st.subheader("📊 Feature Contribution")
            feature_importance = pd.DataFrame({
                'Feature': feature_names,
                'Importance': model.feature_importances_
            }).sort_values('Importance', ascending=False).head(10)
            
            fig = px.bar(
                feature_importance,
                x='Importance',
                y='Feature',
                orientation='h',
                title="Top 10 Most Important Features"
            )
            st.plotly_chart(fig, use_container_width=True)

def show_model_info_page(model, feature_names):
    st.header("📈 Model Information")
    
    tab1, tab2, tab3 = st.tabs(["📊 Performance", "🌲 Model Details", "📚 Documentation"])
    
    with tab1:
        st.subheader("Model Performance Metrics")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            ### Classification Metrics
            - **Accuracy**: 99.65%
            - **ROC-AUC**: 99.98%
            - **Precision**: 100%
            - **Recall**: 99%
            - **F1-Score**: 100%
            """)
        
        with col2:
            # Confusion Matrix visualization
            confusion_matrix_data = np.array([[7073, 0], [44, 5380]])
            
            fig = go.Figure(data=go.Heatmap(
                z=confusion_matrix_data,
                x=['Predicted Ransomware', 'Predicted Benign'],
                y=['True Ransomware', 'True Benign'],
                colorscale='Blues',
                text=confusion_matrix_data,
                texttemplate="%{text}",
                textfont={"size": 20}
            ))
            
            fig.update_layout(
                title="Confusion Matrix",
                xaxis_title="Predicted",
                yaxis_title="Actual"
            )
            
            st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        st.subheader("Random Forest Model Details")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            ### Hyperparameters
            - **Algorithm**: Random Forest Classifier
            - **Number of Trees**: 200
            - **Max Depth**: 20
            - **Random State**: 42
            - **n_jobs**: -1 (all CPU cores)
            """)
        
        with col2:
            st.markdown("""
            ### Training Details
            - **Training Samples**: 49,988
            - **Test Samples**: 12,497
            - **Features**: 15
            - **Test Size**: 20%
            - **Stratified Split**: Yes
            """)
        
        st.subheader("Feature Importance")
        
        # Feature importance plot
        feature_importance = pd.DataFrame({
            'Feature': feature_names,
            'Importance': model.feature_importances_
        }).sort_values('Importance', ascending=False)
        
        fig = px.bar(
            feature_importance,
            x='Importance',
            y='Feature',
            orientation='h',
            title="Feature Importance Ranking"
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with tab3:
        st.subheader("Documentation")
        
        st.markdown("""
        ### About the Dataset
        This model was trained on a dataset of 62,485 PE (Portable Executable) files, 
        including both benign files and ransomware samples.
        
        ### Features Description
        
        | Feature | Description |
        |---------|-------------|
        | Machine | The target machine type (e.g., x86, x64) |
        | DebugSize | Size of debug information |
        | DebugRVA | Relative Virtual Address of debug info |
        | MajorImageVersion | Major version of the image |
        | MajorOSVersion | Major OS version required |
        | ExportRVA | Export table RVA |
        | ExportSize | Size of export table |
        | IatVRA | Import Address Table RVA |
        | MajorLinkerVersion | Linker major version |
        | MinorLinkerVersion | Linker minor version |
        | NumberOfSections | Number of sections in PE |
        | SizeOfStackReserve | Stack reserve size |
        | DllCharacteristics | DLL characteristics flags |
        | ResourceSize | Size of resource section |
        | BitcoinAddresses | Presence of Bitcoin addresses |
        
        ### Usage Guidelines
        
        1. **Batch Analysis**: Upload a CSV file with multiple files to analyze
        2. **Single File Check**: Manually enter file characteristics
        3. **Interpretation**: 
           - Confidence > 70%: High certainty
           - Confidence 30-70%: Medium certainty
           - Confidence < 30%: Low certainty
        
        ### Limitations
        
        - Model is trained on specific PE file characteristics
        - New ransomware variants may exhibit different patterns
        - Regular model updates recommended
        - Should be used as part of layered security approach
        
        ### References
        
        - Random Forest Algorithm: Breiman, L. (2001)
        - PE File Format: Microsoft Documentation
        - Ransomware Detection: Current Research in Malware Analysis
        """)

if __name__ == "__main__":
    main()