#!/usr/bin/env python3
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

class TemplateGenerator:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.templates = {
            'component': self._generate_component_template,
            'api': self._generate_api_template,
            'guide': self._generate_guide_template,
            'example': self._generate_example_template
        }
    
    def _generate_component_template(self, name: str) -> str:
        """Generate a component documentation template."""
        return f"""# {name}

## Overview
Brief description of the {name} component and its purpose.

## Features
- Feature 1
- Feature 2
- Feature 3

## Architecture
```mermaid
graph TD
    A[{name}] --> B[Subcomponent 1]
    A --> C[Subcomponent 2]
    B --> D[Functionality 1]
    C --> E[Functionality 2]
```

## API Reference
### Classes
#### ClassName
```python
class ClassName:
    def method(self, param: type) -> return_type:
        \"\"\"Method description.
        
        Args:
            param: Parameter description
            
        Returns:
            Return value description
        \"\"\"
        pass
```

## Usage Examples
```python
# Example code
from module import ClassName

instance = ClassName()
result = instance.method(param)
```

## Configuration Options
| Option | Type | Default | Description |
|--------|------|---------|-------------|
| option1 | type | default | description |
| option2 | type | default | description |

## Dependencies
- dependency1 >= version
- dependency2 >= version

## Testing
```python
def test_component():
    # Test code
    pass
```

## Performance Considerations
- Performance consideration 1
- Performance consideration 2

## Troubleshooting
### Common Issues
1. Issue 1
   - Solution 1
2. Issue 2
   - Solution 2

## Version History
| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | YYYY-MM-DD | Initial release |

## Contributing
Guidelines for contributing to this component.

## License
[License information]
"""
    
    def _generate_api_template(self, name: str) -> str:
        """Generate an API documentation template."""
        return f"""# {name} API Documentation

## Overview
Description of the {name} API and its purpose.

## Authentication
Details about API authentication.

## Endpoints
### GET /endpoint
```http
GET /api/v1/endpoint
Authorization: Bearer <token>
```

#### Response
```json
{{
    "field": "value"
}}
```

## Error Codes
| Code | Description |
|------|-------------|
| 400 | Bad Request |
| 401 | Unauthorized |
| 404 | Not Found |

## Rate Limiting
Information about rate limits.

## Examples
### Python
```python
import requests

response = requests.get(
    "https://api.example.com/endpoint",
    headers={{"Authorization": "Bearer <token>"}}
)
```

## Versioning
Information about API versioning.

## Support
Contact information for API support.
"""
    
    def _generate_guide_template(self, name: str) -> str:
        """Generate a guide documentation template."""
        return f"""# {name} Guide

## Prerequisites
- Prerequisite 1
- Prerequisite 2

## Installation
```bash
# Installation commands
pip install package
```

## Quick Start
1. Step 1
2. Step 2
3. Step 3

## Detailed Guide
### Section 1
Detailed explanation of section 1.

### Section 2
Detailed explanation of section 2.

## Best Practices
- Best practice 1
- Best practice 2

## Common Pitfalls
- Pitfall 1
  - How to avoid
- Pitfall 2
  - How to avoid

## Additional Resources
- [Resource 1](link)
- [Resource 2](link)
"""
    
    def _generate_example_template(self, name: str) -> str:
        """Generate an example documentation template."""
        return f"""# {name} Example

## Overview
Description of the example and what it demonstrates.

## Prerequisites
- Prerequisite 1
- Prerequisite 2

## Setup
```bash
# Setup commands
git clone repository
cd directory
pip install -r requirements.txt
```

## Code
```python
# Example code
def main():
    # Code implementation
    pass

if __name__ == "__main__":
    main()
```

## Explanation
Detailed explanation of the code and its functionality.

## Running the Example
```bash
# Run commands
python example.py
```

## Expected Output
```
# Expected output
output
```

## Troubleshooting
Common issues and their solutions.

## Extending the Example
How to extend or modify the example.
"""
    
    def generate(self, template_type: str, name: str, output_file: Optional[str] = None) -> None:
        """Generate a documentation template."""
        if template_type not in self.templates:
            print(f"Unknown template type: {template_type}")
            print(f"Available types: {', '.join(self.templates.keys())}")
            sys.exit(1)
        
        content = self.templates[template_type](name)
        
        if output_file is None:
            output_file = f"{name.lower().replace(' ', '_')}.md"
        
        output_path = self.output_dir / output_file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"Template generated: {output_path}")

def main():
    if len(sys.argv) < 3:
        print("Usage: python generate_template.py <template_type> <name> [output_file]")
        print("Available template types:")
        print("- component: Component documentation template")
        print("- api: API documentation template")
        print("- guide: Guide documentation template")
        print("- example: Example documentation template")
        sys.exit(1)
    
    template_type = sys.argv[1]
    name = sys.argv[2]
    output_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    generator = TemplateGenerator('docs/templates')
    generator.generate(template_type, name, output_file)

if __name__ == '__main__':
    main() 