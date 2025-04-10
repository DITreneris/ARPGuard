"""
ARP Guard Help Search

This module provides search functionality for the ARP Guard help system,
allowing users to search for commands, options, and topics.
"""

import re
from typing import List, Dict, Any, Tuple
import difflib
from collections import Counter

# This would normally be imported, but for completeness we'll include a simplified version
HELP_CONTENT = {
    "main": {
        "description": "ARP Guard is a powerful network security tool that monitors and protects against ARP spoofing attacks.",
        "keywords": ["arp", "security", "network", "monitor", "protection", "spoofing"]
    },
    "start": {
        "description": "Start the ARP Guard service to begin monitoring network traffic for ARP spoofing attacks.",
        "keywords": ["start", "run", "monitor", "service", "background", "daemon"]
    },
    "stop": {
        "description": "Stop the ARP Guard service. This command will gracefully shut down the service.",
        "keywords": ["stop", "end", "halt", "kill", "terminate", "shutdown"]
    },
    "status": {
        "description": "Display the current status of the ARP Guard service.",
        "keywords": ["status", "state", "running", "info", "information", "details", "health"]
    },
    "config": {
        "description": "Manage ARP Guard configuration settings.",
        "keywords": ["config", "configure", "settings", "options", "preferences", "setup"]
    },
    "logs": {
        "description": "View and manage ARP Guard logs.",
        "keywords": ["logs", "log", "history", "output", "messages", "events", "errors"]
    }
}

# Topic index for conceptual searching
TOPICS = {
    "installation": ["install", "setup", "configure", "start", "requirements"],
    "monitoring": ["monitoring", "detection", "alerts", "status", "start"],
    "configuration": ["config", "settings", "options", "customize", "modify"],
    "troubleshooting": ["error", "problem", "issue", "debug", "logs", "fix"],
    "security": ["attack", "vulnerability", "spoofing", "protection", "prevent"],
    "performance": ["speed", "optimization", "resource", "memory", "cpu"],
    "alerts": ["notification", "alert", "warning", "message", "email"],
    "network": ["interface", "ethernet", "wifi", "protocol", "arp", "mac", "ip"]
}

def tokenize_query(query: str) -> List[str]:
    """Split query into individual tokens and lowercase them."""
    # Remove special characters and split by whitespace
    tokens = re.sub(r'[^\w\s]', ' ', query.lower()).split()
    # Filter out common stop words
    stop_words = {'the', 'and', 'a', 'an', 'in', 'on', 'at', 'to', 'for', 'with', 'how', 'what', 'when', 'where', 'why'}
    return [token for token in tokens if token not in stop_words and len(token) > 1]

def calculate_relevance(command: str, tokens: List[str], help_data: Dict[str, Any]) -> float:
    """Calculate relevance score for a command based on search tokens."""
    score = 0.0
    
    # Check command name
    for token in tokens:
        if token in command:
            score += 3.0  # Highest weight for command name match
            
    # Check description
    description = help_data.get("description", "").lower()
    for token in tokens:
        if token in description:
            score += 2.0  # High weight for description match
    
    # Check keywords
    keywords = help_data.get("keywords", [])
    for token in tokens:
        for keyword in keywords:
            if token in keyword or keyword in token:
                score += 1.0  # Standard weight for keyword match
                # Exact keyword match gets bonus
                if token == keyword:
                    score += 0.5
    
    return score

def find_related_topics(tokens: List[str]) -> List[Tuple[str, float]]:
    """Find topics related to the search tokens."""
    topic_scores = []
    
    for topic, keywords in TOPICS.items():
        score = 0.0
        for token in tokens:
            # Direct match with topic name
            if token in topic:
                score += 2.0
            
            # Match with topic keywords
            for keyword in keywords:
                if token in keyword or keyword in token:
                    score += 1.0
                    # Exact match gets bonus
                    if token == keyword:
                        score += 0.5
        
        if score > 0:
            topic_scores.append((topic, score))
    
    # Sort by score descending
    return sorted(topic_scores, key=lambda x: x[1], reverse=True)

def search_help(query: str, top_n: int = 5) -> Dict[str, Any]:
    """Search help content and return relevant results."""
    tokens = tokenize_query(query)
    
    if not tokens:
        return {
            "commands": [],
            "topics": [],
            "did_you_mean": []
        }
    
    # Calculate scores for each command
    command_scores = []
    for command, help_data in HELP_CONTENT.items():
        score = calculate_relevance(command, tokens, help_data)
        if score > 0:
            command_scores.append((command, score))
    
    # Sort by score descending
    command_scores = sorted(command_scores, key=lambda x: x[1], reverse=True)
    
    # Find related topics
    topic_scores = find_related_topics(tokens)
    
    # Generate "did you mean" suggestions using word similarity
    all_words = []
    for help_data in HELP_CONTENT.values():
        all_words.extend(help_data.get("keywords", []))
    
    did_you_mean = []
    for token in tokens:
        if len(token) > 3:  # Only suggest for tokens of reasonable length
            matches = difflib.get_close_matches(token, all_words, n=2, cutoff=0.7)
            did_you_mean.extend([m for m in matches if m != token])
    
    # Remove duplicates while preserving order
    did_you_mean = list(dict.fromkeys(did_you_mean))
    
    return {
        "commands": command_scores[:top_n],
        "topics": topic_scores[:top_n],
        "did_you_mean": did_you_mean[:5]
    }

def extract_contextual_help(query: str) -> Dict[str, Any]:
    """Extract contextual help based on a natural language query."""
    # Common question patterns
    patterns = {
        r"how\s+(?:do\s+)?(?:I|you)\s+(.+?)(?:\s+in\s+arp\s*guard|\?|$)": "how_to",
        r"what\s+(?:does|is)\s+(?:the)?\s*(.+?)(?:\s+(?:command|option|in\s+arp\s*guard)|\?|$)": "what_is",
        r"(?:can|is\s+it\s+possible\s+to)\s+(.+?)(?:\s+with\s+arp\s*guard|\?|$)": "capability",
        r"(?:why|when)\s+(?:does|should|would|is|are)\s+(.+?)(?:\?|$)": "explanation",
        r"(?:show|display|view)\s+(.+?)(?:\s+for\s+arp\s*guard|\?|$)": "show_info"
    }
    
    for pattern, intent in patterns.items():
        match = re.search(pattern, query.lower())
        if match:
            subject = match.group(1).strip()
            
            # Get search results based on the subject
            search_results = search_help(subject)
            
            return {
                "intent": intent,
                "subject": subject,
                "search_results": search_results,
                "matched_pattern": pattern
            }
    
    # No specific pattern matched, perform general search
    return {
        "intent": "general",
        "subject": query,
        "search_results": search_help(query),
        "matched_pattern": None
    }

def format_search_results(results: Dict[str, Any]) -> str:
    """Format search results into readable text."""
    output = []
    
    # Commands section
    if results["commands"]:
        output.append("RELEVANT COMMANDS:")
        for cmd, score in results["commands"]:
            description = HELP_CONTENT[cmd]["description"]
            short_desc = description[:80] + "..." if len(description) > 80 else description
            output.append(f"  - {cmd}: {short_desc}")
    
    # Topics section
    if results["topics"]:
        output.append("\nRELATED TOPICS:")
        for topic, score in results["topics"]:
            output.append(f"  - {topic.title()}: Use 'arp-guard help {topic}' for more information")
    
    # Did you mean section
    if results["did_you_mean"]:
        output.append("\nDID YOU MEAN:")
        output.append(f"  - {', '.join(results['did_you_mean'])}")
    
    # No results
    if not results["commands"] and not results["topics"]:
        output.append("No results found. Try different search terms or use 'arp-guard help' for general help.")
    
    return "\n".join(output)

def process_help_query(query: str) -> str:
    """Process a help query and return formatted response."""
    contextual_data = extract_contextual_help(query)
    search_results = contextual_data["search_results"]
    
    # Format the output based on the intent
    if contextual_data["intent"] == "how_to":
        response = f"To {contextual_data['subject']}, you can use the following commands:\n\n"
        response += format_search_results(search_results)
    elif contextual_data["intent"] == "what_is":
        response = f"Information about {contextual_data['subject']}:\n\n"
        response += format_search_results(search_results)
    elif contextual_data["intent"] == "capability":
        response = f"To {contextual_data['subject']}, you can use these features:\n\n"
        response += format_search_results(search_results)
    elif contextual_data["intent"] == "explanation":
        response = f"Regarding {contextual_data['subject']}:\n\n"
        response += format_search_results(search_results)
    elif contextual_data["intent"] == "show_info":
        response = f"Information about {contextual_data['subject']}:\n\n"
        response += format_search_results(search_results)
    else:
        response = f"Search results for '{query}':\n\n"
        response += format_search_results(search_results)
    
    return response

if __name__ == "__main__":
    # Example usage
    while True:
        query = input("\nEnter a help query (or 'exit' to quit): ")
        if query.lower() == 'exit':
            break
        
        print("\n" + process_help_query(query)) 