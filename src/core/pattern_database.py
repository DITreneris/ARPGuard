import json
import logging
import os
import time
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Any, TypedDict, Union, Tuple
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)

class PatternMatchType(Enum):
    """Type of pattern match"""
    EXACT = auto()      # Exact matching (all elements must match exactly)
    PARTIAL = auto()    # Partial matching (subset of elements must match)
    FUZZY = auto()      # Fuzzy matching (using similarity threshold)
    REGEX = auto()      # Regular expression matching


class PatternCategory(Enum):
    """Category of attack pattern"""
    ARP_SPOOFING = auto()
    ARP_POISONING = auto()
    ARP_DOS = auto()
    ARP_MITM = auto()
    GATEWAY_IMPERSONATION = auto()
    MAC_FLOODING = auto()
    CUSTOM = auto()


@dataclass
class PatternFeature:
    """A feature in a pattern, with name, value and match type"""
    name: str
    value: Any
    match_type: PatternMatchType = PatternMatchType.EXACT
    weight: float = 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "name": self.name,
            "value": self.value,
            "match_type": self.match_type.name,
            "weight": self.weight
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PatternFeature':
        """Create from dictionary representation"""
        return cls(
            name=data["name"],
            value=data["value"],
            match_type=PatternMatchType[data["match_type"]],
            weight=data.get("weight", 1.0)
        )


@dataclass
class Pattern:
    """A pattern representing an ARP attack sequence"""
    id: str
    name: str
    description: str
    category: PatternCategory
    features: List[PatternFeature]
    confidence: float = 0.7  # Default confidence threshold
    severity: int = 5        # 1-10 scale
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category.name,
            "features": [f.to_dict() for f in self.features],
            "confidence": self.confidence,
            "severity": self.severity,
            "references": self.references,
            "tags": self.tags,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Pattern':
        """Create from dictionary representation"""
        return cls(
            id=data["id"],
            name=data["name"],
            description=data["description"],
            category=PatternCategory[data["category"]],
            features=[PatternFeature.from_dict(f) for f in data["features"]],
            confidence=data.get("confidence", 0.7),
            severity=data.get("severity", 5),
            references=data.get("references", []),
            tags=data.get("tags", []),
            created_at=data.get("created_at", time.time()),
            updated_at=data.get("updated_at", time.time())
        )


class PatternDatabase:
    """
    Database for storing, retrieving, and matching ARP attack patterns.
    """
    
    def __init__(self, database_path: Optional[str] = None):
        """
        Initialize pattern database.
        
        Args:
            database_path: Path to the pattern database file.
                           If None, patterns will only be kept in memory.
        """
        self.database_path = database_path
        self.patterns: Dict[str, Pattern] = {}  # id -> Pattern
        self.pattern_by_tag: Dict[str, Set[str]] = {}  # tag -> set of pattern IDs
        self.pattern_by_category: Dict[PatternCategory, Set[str]] = {}  # category -> set of pattern IDs
        
        # Load patterns if database path provided
        if database_path and os.path.exists(database_path):
            self.load()
        else:
            self._initialize_default_patterns()
    
    def _initialize_default_patterns(self) -> None:
        """Initialize with default ARP attack patterns"""
        # Classic ARP spoofing pattern
        arp_spoof = Pattern(
            id="ARP-SPOOF-001",
            name="Classic ARP Spoofing",
            description="Classic ARP spoofing attack where attacker claims to be the gateway",
            category=PatternCategory.ARP_SPOOFING,
            features=[
                PatternFeature("is_at_request", False),
                PatternFeature("is_gratuitous", True),
                PatternFeature("target_is_gateway", True),
                PatternFeature("rapid_changes", True)
            ],
            confidence=0.8,
            severity=8,
            tags=["arp", "spoofing", "gateway", "mitm"]
        )
        
        # Gateway impersonation pattern
        gateway_impersonation = Pattern(
            id="ARP-SPOOF-002",
            name="Gateway Impersonation",
            description="Attacker impersonates the gateway by sending gratuitous ARP responses",
            category=PatternCategory.GATEWAY_IMPERSONATION,
            features=[
                PatternFeature("is_at_request", False),
                PatternFeature("is_gratuitous", True),
                PatternFeature("sender_is_gateway_ip", False),
                PatternFeature("gateway_mac_changed", True)
            ],
            confidence=0.85,
            severity=9,
            tags=["arp", "gateway", "impersonation"]
        )
        
        # ARP DoS attack pattern
        arp_dos = Pattern(
            id="ARP-DOS-001",
            name="ARP DoS Attack",
            description="Denial of service via ARP flooding",
            category=PatternCategory.ARP_DOS,
            features=[
                PatternFeature("packet_rate_high", True),
                PatternFeature("multiple_targets", True),
                PatternFeature("random_mac_addresses", True)
            ],
            confidence=0.75,
            severity=7,
            tags=["arp", "dos", "flooding"]
        )
        
        # Add patterns to database
        for pattern in [arp_spoof, gateway_impersonation, arp_dos]:
            self.add_pattern(pattern)
    
    def add_pattern(self, pattern: Pattern) -> None:
        """
        Add a pattern to the database.
        
        Args:
            pattern: The pattern to add
        """
        # Set updated time
        pattern.updated_at = time.time()
        
        # Add to main patterns dictionary
        self.patterns[pattern.id] = pattern
        
        # Add to tag index
        for tag in pattern.tags:
            if tag not in self.pattern_by_tag:
                self.pattern_by_tag[tag] = set()
            self.pattern_by_tag[tag].add(pattern.id)
        
        # Add to category index
        if pattern.category not in self.pattern_by_category:
            self.pattern_by_category[pattern.category] = set()
        self.pattern_by_category[pattern.category].add(pattern.id)
        
        logger.info(f"Added pattern: {pattern.id} - {pattern.name}")
        
        # Save to disk if database path provided
        if self.database_path:
            self.save()
    
    def remove_pattern(self, pattern_id: str) -> bool:
        """
        Remove a pattern from the database.
        
        Args:
            pattern_id: ID of the pattern to remove
            
        Returns:
            True if pattern was removed, False if it wasn't found
        """
        if pattern_id not in self.patterns:
            return False
        
        pattern = self.patterns[pattern_id]
        
        # Remove from main patterns dictionary
        del self.patterns[pattern_id]
        
        # Remove from tag index
        for tag in pattern.tags:
            if tag in self.pattern_by_tag:
                if pattern_id in self.pattern_by_tag[tag]:
                    self.pattern_by_tag[tag].remove(pattern_id)
                
                # Remove tag if no patterns left
                if not self.pattern_by_tag[tag]:
                    del self.pattern_by_tag[tag]
        
        # Remove from category index
        if pattern.category in self.pattern_by_category:
            if pattern_id in self.pattern_by_category[pattern.category]:
                self.pattern_by_category[pattern.category].remove(pattern_id)
            
            # Remove category if no patterns left
            if not self.pattern_by_category[pattern.category]:
                del self.pattern_by_category[pattern.category]
        
        logger.info(f"Removed pattern: {pattern_id}")
        
        # Save to disk if database path provided
        if self.database_path:
            self.save()
            
        return True
    
    def get_pattern(self, pattern_id: str) -> Optional[Pattern]:
        """
        Get a pattern by ID.
        
        Args:
            pattern_id: ID of the pattern to retrieve
            
        Returns:
            The pattern if found, None otherwise
        """
        return self.patterns.get(pattern_id)
    
    def get_patterns_by_tag(self, tag: str) -> List[Pattern]:
        """
        Get patterns by tag.
        
        Args:
            tag: Tag to search for
            
        Returns:
            List of patterns with the given tag
        """
        if tag not in self.pattern_by_tag:
            return []
        
        return [self.patterns[pattern_id] for pattern_id in self.pattern_by_tag[tag]]
    
    def get_patterns_by_category(self, category: PatternCategory) -> List[Pattern]:
        """
        Get patterns by category.
        
        Args:
            category: Category to search for
            
        Returns:
            List of patterns in the given category
        """
        if category not in self.pattern_by_category:
            return []
        
        return [self.patterns[pattern_id] for pattern_id in self.pattern_by_category[category]]
    
    def get_all_patterns(self) -> List[Pattern]:
        """
        Get all patterns in the database.
        
        Returns:
            List of all patterns
        """
        return list(self.patterns.values())
    
    def save(self) -> bool:
        """
        Save the pattern database to disk.
        
        Returns:
            True if successful, False otherwise
        """
        if not self.database_path:
            logger.warning("No database path provided, cannot save patterns")
            return False
        
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.database_path), exist_ok=True)
            
            # Convert patterns to dictionaries
            patterns_dict = {
                pattern_id: pattern.to_dict() 
                for pattern_id, pattern in self.patterns.items()
            }
            
            # Write to file
            with open(self.database_path, "w") as f:
                json.dump(patterns_dict, f, indent=2)
                
            logger.info(f"Saved {len(self.patterns)} patterns to {self.database_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving patterns to {self.database_path}: {e}")
            return False
    
    def load(self) -> bool:
        """
        Load the pattern database from disk.
        
        Returns:
            True if successful, False otherwise
        """
        if not self.database_path or not os.path.exists(self.database_path):
            logger.warning(f"Pattern database file not found: {self.database_path}")
            return False
        
        try:
            # Clear existing patterns
            self.patterns = {}
            self.pattern_by_tag = {}
            self.pattern_by_category = {}
            
            # Read from file
            with open(self.database_path, "r") as f:
                patterns_dict = json.load(f)
            
            # Convert dictionaries to patterns
            for pattern_id, pattern_data in patterns_dict.items():
                pattern = Pattern.from_dict(pattern_data)
                self.add_pattern(pattern)
                
            logger.info(f"Loaded {len(self.patterns)} patterns from {self.database_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading patterns from {self.database_path}: {e}")
            return False 