# ML Component Tests

This directory contains tests for the Machine Learning components of ARPGuard.

## Implemented Tests

### Feature Engineering
- **Feature Extraction**: `tests/ml/test_feature_extraction.py`
  - Tests for extraction of basic features, temporal features, relationship features, network features
  - Tests for complete feature extraction pipeline
  - Tests for error handling and packet window management

- **Feature Processing**: 
  - **Preprocessor**: `tests/ml/features/test_preprocessor.py`
    - Tests for data preprocessing, PCA dimensionality reduction
    - Tests for timestamp processing
    - Tests for feature importance calculation and inverse transformation
  - **Performance Metrics**: `tests/ml/features/test_performance_metrics.py`
    - Tests for system performance metrics collection
    - Tests for metrics history management
    - Tests for different data window retrievals

## Running the Tests

### Prerequisites
- Python 3.8+
- Required packages installed via `pip install -r requirements.txt`

### Running Individual Test Files
```bash
# Run feature extraction tests
python -m unittest tests/ml/test_feature_extraction.py

# Run preprocessor tests
python -m unittest tests/ml/features/test_preprocessor.py

# Run performance metrics tests
python -m unittest tests/ml/features/test_performance_metrics.py
```

### Running All ML Tests
Use the ML test runner script:
```bash
python scripts/run_ml_tests.py --all
```

### Options for the Test Runner
- `--all`: Run all ML tests
- `--feature-extraction`: Run only feature extraction tests
- `--preprocessing`: Run only preprocessing tests
- `--models`: Run only model tests
- `--pipeline`: Run only pipeline tests
- `--performance`: Run only performance tests
- `--coverage`: Generate coverage report

## Test Coverage

Current test coverage for ML Components:
- Feature Engineering: 5/8 tests implemented (63%)
  - Feature Extraction: 3/3 tests implemented (100%)
  - Feature Processing: 2/3 tests implemented (67%)
  - Feature Validation: 0/2 tests implemented (0%)

## Upcoming Tests

- Model Architecture Tests
  - Ensemble Models
  - Deep Learning Models
  - Online Learning
- Pipeline Component Tests
  - Data Collection
  - Preprocessing
  - Model Training
  - Model Evaluation
- Performance Metrics Tests
  - Accuracy Tests
  - Latency Tests
  - Resource Usage Tests 