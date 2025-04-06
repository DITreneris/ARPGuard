# Contributing to ARPGuard

Thank you for considering contributing to ARPGuard! This document outlines the process for contributing to the project and provides guidelines to make the process smooth and effective.

## Code of Conduct

By participating in this project, you are expected to uphold our Code of Conduct: be respectful, considerate, and constructive in all interactions.

## How Can I Contribute?

### Reporting Bugs

- **Check existing issues** to see if the bug has already been reported
- **Use the bug report template** if one is provided
- **Include detailed information** about your environment (OS, Python version, etc.)
- **Provide steps to reproduce** the issue
- **Include screenshots or logs** if possible

### Suggesting Enhancements

- **Clearly describe the enhancement** and its expected benefits
- **Provide examples and use cases** to illustrate the need
- **Consider implementation details** if you can

### Pull Requests

1. **Fork the repository** to your GitHub account
2. **Create a branch** for your feature or fix
3. **Make your changes**, following the coding standards
4. **Write or update tests** for your changes
5. **Run the test suite** to ensure all tests pass
6. **Submit a pull request** targeting the `main` branch

## Development Environment Setup

1. Clone your fork of the repository:
   ```
   git clone https://github.com/yourusername/arpguard.git
   cd arpguard
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install development dependencies:
   ```
   pip install -r requirements.txt
   pip install pytest pytest-cov pylint black
   ```

4. Set up pre-commit hooks:
   ```
   pip install pre-commit
   pre-commit install
   ```

## Coding Standards

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) for Python code
- Add type hints to all new functions and methods
- Write docstrings for all modules, classes, and functions
- Keep line length to 100 characters or less
- Use meaningful variable and function names

## Testing

- Write unit tests for all new functionality
- Ensure all tests pass before submitting a pull request
- Aim for high test coverage (>80%)

To run tests:
```
python run.py test --coverage
```

## Documentation

- Update documentation for any changed functionality
- Document new features thoroughly
- Use clear, concise language

## Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Fix bug" not "Fixes bug")
- Limit the first line to 72 characters or less
- Reference issues and pull requests after the first line
- Consider using the following format:
  ```
  Type(scope): Short description

  Longer description if necessary

  Fixes #123
  ```
  where "Type" can be one of: feat, fix, docs, style, refactor, test, chore

## Review Process

1. All pull requests require review before merging
2. Address any requested changes
3. Ensure CI tests pass
4. Once approved, a maintainer will merge your changes

## Questions?

If you have any questions or need help, you can:
- Open an issue for discussion
- Contact the maintainers directly
- Join our community channels

Thank you for contributing to ARPGuard! 