# Contributing to ARP Guard

Thank you for your interest in contributing to ARP Guard! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Development Environment Setup

### Prerequisites
- Python 3.11 or higher
- Git
- Virtual environment (recommended)

### Installation Steps
1. Fork and clone the repository:
   ```bash
   git clone https://github.com/your-username/arp-guard.git
   cd arp-guard
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install development dependencies:
   ```bash
   pip install -r requirements-dev.txt
   ```

4. Install ARP Guard in development mode:
   ```bash
   pip install -e .
   ```

## Code Style Guidelines

We follow PEP 8 with some additional guidelines:

- Use type hints for all function parameters and return values
- Document all public functions and classes with docstrings
- Keep functions focused and small (ideally under 50 lines)
- Use meaningful variable and function names
- Add comments for complex logic

### Running Code Style Checks
```bash
# Run flake8
flake8 src tests

# Run black for code formatting
black src tests

# Run isort for import sorting
isort src tests
```

## Testing

### Running Tests
```bash
# Run all tests
pytest

# Run tests with coverage
pytest --cov=src tests/

# Run specific test file
pytest tests/test_detection.py
```

### Writing Tests
- Follow pytest conventions
- Use descriptive test names
- Include docstrings explaining test purpose
- Use fixtures for common setup
- Mock external dependencies

## Pull Request Process

1. Create a new branch for your feature/fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and commit them:
   ```bash
   git commit -m "feat: add new feature"
   ```

3. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

4. Create a Pull Request:
   - Fill out the PR template
   - Link related issues
   - Request review from maintainers

### Commit Message Format
```
<type>: <description>

[optional body]

[optional footer]
```

Types:
- feat: New feature
- fix: Bug fix
- docs: Documentation changes
- style: Code style changes
- refactor: Code refactoring
- test: Test changes
- chore: Maintenance tasks

## Documentation

### Writing Documentation
- Use clear, concise language
- Include code examples where helpful
- Keep documentation up to date with code changes
- Use proper formatting and structure

### Building Documentation
```bash
# Install documentation dependencies
pip install -r requirements-docs.txt

# Build documentation
cd docs
make html
```

## Security

- Report security vulnerabilities privately to security@arpguard.com
- Do not include sensitive information in issues or PRs
- Follow secure coding practices
- Review security implications of changes

## Getting Help

- Check the [documentation](docs/)
- Search existing issues
- Join our [Discord community](https://discord.gg/arpguard)
- Create a new issue if needed

## License

By contributing to ARP Guard, you agree that your contributions will be licensed under the project's [LICENSE](LICENSE) file. 