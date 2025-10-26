# 🛡️ Ransomware Detection System

A machine learning-powered web application for detecting ransomware based on PE file characteristics.

## 📋 Project Structure

```
ransomware_detection_app/
│
├── models/
│   └── ransomware_model.pkl    # Trained model + feature list
│
├── notebooks/
│   └── train_model.ipynb       # Model training notebook
│
├── data/
│   └── data_file.csv           # Training dataset
│
├── app.py                      # Streamlit application
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

## 🚀 Quick Start

### 1. Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### 2. Installation

```bash
# Clone or download the project
cd ransomware_detection_app

# Create a virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Prepare the Model

Make sure you have the trained model file in the `models/` directory:
- `models/ransomware_model.pkl` (should contain both the model and feature list)

If you need to train the model first:
```bash
# Run the training notebook
jupyter notebook notebooks/train_model.ipynb
```

### 4. Run the Application

```bash
streamlit run app.py
```

The app will open automatically in your default web browser at `http://localhost:8501`

## 📱 Features

### 🏠 Home Page
- Overview of model performance
- Key metrics (99.65% accuracy)
- How it works explanation

### 📊 Batch Analysis
- Upload CSV files with multiple files
- Analyze hundreds of files at once
- Visual analytics and statistics
- Download results as CSV
- Filter by detection type

### 🔍 Single File Check
- Manual entry for individual files
- Real-time prediction
- Feature importance visualization
- Risk level assessment

### 📈 Model Info
- Detailed performance metrics
- Confusion matrix
- Feature importance rankings
- Comprehensive documentation

## 📊 Input Format

### For Batch Analysis (CSV)

Your CSV file should contain the following columns:

| Column Name | Type | Description |
|-------------|------|-------------|
| Machine | int | Target machine type |
| DebugSize | int | Debug information size |
| DebugRVA | int | Debug RVA |
| MajorImageVersion | int | Image major version |
| MajorOSVersion | int | OS major version |
| ExportRVA | int | Export table RVA |
| ExportSize | int | Export table size |
| IatVRA | int | Import Address Table RVA |
| MajorLinkerVersion | int | Linker major version |
| MinorLinkerVersion | int | Linker minor version |
| NumberOfSections | int | Number of sections |
| SizeOfStackReserve | int | Stack reserve size |
| DllCharacteristics | int | DLL characteristics |
| ResourceSize | int | Resource section size |
| BitcoinAddresses | int | Bitcoin address count |

**Example CSV:**
```csv
Machine,DebugSize,DebugRVA,MajorImageVersion,MajorOSVersion,ExportRVA,ExportSize,IatVRA,MajorLinkerVersion,MinorLinkerVersion,NumberOfSections,SizeOfStackReserve,DllCharacteristics,ResourceSize,BitcoinAddresses
332,0,0,0,4,0,0,8192,8,0,3,1048576,34112,672,0
34404,84,121728,10,10,126576,4930,0,14,10,8,262144,16864,1024,0
```

### For Single File Check

Enter values manually in the web interface.

## 🎯 Model Performance

- **Accuracy**: 99.65%
- **ROC-AUC**: 99.98%
- **Precision**: 100% (Ransomware class)
- **Recall**: 99% (Ransomware class)
- **F1-Score**: 100% (Ransomware class)

## 🔧 Customization

### Changing Model Parameters

Edit the model training section in `notebooks/train_model.ipynb`:

```python
model = RandomForestClassifier(
    n_estimators=200,       # Number of trees
    max_depth=20,           # Maximum depth
    random_state=42,
    n_jobs=-1
)
```

### Updating the App Theme

Modify the CSS in `app.py`:

```python
st.markdown("""
    <style>
    .main-header {
        color: #1f77b4;  # Change header color
    }
    </style>
""", unsafe_allow_html=True)
```

## 🐛 Troubleshooting

### Model File Not Found
```
Error: Failed to load the model
```
**Solution**: Ensure `models/ransomware_model.pkl` exists and contains both model and features.

### Missing Columns Error
```
Error: Missing required columns
```
**Solution**: Check that your CSV file has all 15 required feature columns with exact names.

### Import Errors
```
ModuleNotFoundError: No module named 'streamlit'
```
**Solution**: Reinstall dependencies:
```bash
pip install -r requirements.txt
```

## 📚 Dependencies

- **streamlit**: Web application framework
- **pandas**: Data manipulation
- **numpy**: Numerical computations
- **scikit-learn**: Machine learning
- **joblib**: Model serialization
- **plotly**: Interactive visualizations

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## ⚠️ Disclaimer

This tool is for educational and research purposes. It should be used as part of a comprehensive security strategy, not as a standalone solution. Regular updates and retraining are recommended for optimal performance.

## 📄 License

This project is open source and available under the MIT License.

## 📧 Support

For issues, questions, or suggestions, please open an issue in the repository.

---
