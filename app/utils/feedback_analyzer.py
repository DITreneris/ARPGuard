import re
import json
import logging
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple, Counter
from datetime import datetime
from collections import defaultdict
import nltk
from nltk.sentiment import SentimentIntensityAnalyzer
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
import matplotlib.pyplot as plt
import io
import base64

logger = logging.getLogger("arp_guard.utils.feedback_analyzer")

# Initialize NLTK resources
try:
    nltk.data.find('tokenizers/punkt')
    nltk.data.find('sentiment/vader_lexicon.zip')
    nltk.data.find('corpora/stopwords')
except LookupError:
    logger.info("Downloading NLTK resources...")
    nltk.download('punkt')
    nltk.download('vader_lexicon')
    nltk.download('stopwords')

class FeedbackAnalyzer:
    """Tool for analyzing beta tester feedback"""
    
    def __init__(self):
        """Initialize the feedback analyzer"""
        self.sentiment_analyzer = SentimentIntensityAnalyzer()
        self.stop_words = set(stopwords.words('english'))
        self.feedback_data = []
        self.categories = {
            'ui': ['interface', 'ui', 'gui', 'button', 'display', 'screen', 'view'],
            'performance': ['slow', 'fast', 'performance', 'speed', 'lag', 'responsive', 'memory', 'cpu'],
            'features': ['feature', 'functionality', 'capability', 'function', 'tool'],
            'bugs': ['bug', 'crash', 'error', 'issue', 'problem', 'fail', 'failure', 'fix'],
            'security': ['security', 'vulnerability', 'secure', 'protect', 'encryption', 'threat', 'attack'],
            'usability': ['usability', 'user-friendly', 'intuitive', 'confusing', 'easy', 'difficult', 'complex'],
            'documentation': ['documentation', 'docs', 'help', 'guide', 'tutorial', 'manual', 'explanation'],
            'suggestions': ['suggest', 'recommendation', 'improve', 'enhancement', 'add', 'new']
        }
        
        # Create a mapping of words to categories for faster lookup
        self.word_to_category = {}
        for category, words in self.categories.items():
            for word in words:
                self.word_to_category[word] = category
        
        # Version specific feedback tracking
        self.version_data = {}
        
        logger.info("Feedback analyzer initialized")
    
    def load_feedback(self, file_path: str) -> bool:
        """
        Load feedback data from a JSON or CSV file
        
        Args:
            file_path: Path to the feedback data file
            
        Returns:
            True if loaded successfully
        """
        try:
            if file_path.endswith('.json'):
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        self.feedback_data.extend(data)
                    else:
                        self.feedback_data.append(data)
            elif file_path.endswith('.csv'):
                df = pd.read_csv(file_path)
                self.feedback_data.extend(df.to_dict('records'))
            else:
                logger.error(f"Unsupported file format: {file_path}")
                return False
                
            logger.info(f"Loaded {len(self.feedback_data)} feedback entries from {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load feedback data: {str(e)}")
            return False
    
    def add_feedback(self, feedback: Dict[str, Any]) -> bool:
        """
        Add a single feedback entry
        
        Args:
            feedback: Dictionary containing feedback data
            
        Returns:
            True if added successfully
        """
        # Add timestamp if not present
        if 'timestamp' not in feedback:
            feedback['timestamp'] = datetime.now().isoformat()
            
        # Ensure required fields
        required_fields = ['text', 'user_id']
        for field in required_fields:
            if field not in feedback:
                logger.error(f"Missing required field: {field}")
                return False
                
        self.feedback_data.append(feedback)
        
        # Track by version if available
        if 'version' in feedback:
            version = feedback['version']
            if version not in self.version_data:
                self.version_data[version] = []
            self.version_data[version].append(feedback)
            
        return True
    
    def _preprocess_text(self, text: str) -> List[str]:
        """
        Preprocess text for analysis
        
        Args:
            text: Text to preprocess
            
        Returns:
            List of tokens
        """
        # Convert to lowercase
        text = text.lower()
        
        # Tokenize
        tokens = word_tokenize(text)
        
        # Remove stopwords and punctuation
        tokens = [word for word in tokens if word.isalpha() and word not in self.stop_words]
        
        return tokens
    
    def _get_sentiment(self, text: str) -> Dict[str, float]:
        """
        Get sentiment scores for text
        
        Args:
            text: Text to analyze
            
        Returns:
            Dictionary with sentiment scores
        """
        return self.sentiment_analyzer.polarity_scores(text)
    
    def _categorize_feedback(self, text: str) -> Dict[str, float]:
        """
        Categorize feedback text
        
        Args:
            text: Feedback text
            
        Returns:
            Dictionary with category scores
        """
        tokens = self._preprocess_text(text)
        
        # Count category occurrences
        category_counts = defaultdict(int)
        for token in tokens:
            if token in self.word_to_category:
                category = self.word_to_category[token]
                category_counts[category] += 1
        
        # If we found categories, normalize the scores
        if category_counts:
            total = sum(category_counts.values())
            category_scores = {category: count / total for category, count in category_counts.items()}
        else:
            # If no categories found, mark as uncategorized
            category_scores = {'uncategorized': 1.0}
        
        return category_scores
    
    def analyze_feedback(self, feedback_idx: Optional[int] = None) -> Dict[str, Any]:
        """
        Analyze a specific feedback entry or all feedback
        
        Args:
            feedback_idx: Index of the feedback to analyze (None for all)
            
        Returns:
            Dictionary with analysis results
        """
        if feedback_idx is not None:
            if feedback_idx < 0 or feedback_idx >= len(self.feedback_data):
                logger.error(f"Invalid feedback index: {feedback_idx}")
                return {}
                
            feedback = self.feedback_data[feedback_idx]
            text = feedback.get('text', '')
            
            sentiment = self._get_sentiment(text)
            categories = self._categorize_feedback(text)
            
            return {
                'feedback': feedback,
                'sentiment': sentiment,
                'categories': categories
            }
        else:
            # Analyze all feedback
            results = []
            overall_sentiment = {
                'pos': 0.0,
                'neg': 0.0,
                'neu': 0.0,
                'compound': 0.0
            }
            category_distribution = defaultdict(int)
            
            for feedback in self.feedback_data:
                text = feedback.get('text', '')
                sentiment = self._get_sentiment(text)
                categories = self._categorize_feedback(text)
                
                # Update overall sentiment
                for key in overall_sentiment:
                    overall_sentiment[key] += sentiment.get(key, 0.0)
                
                # Update category distribution
                primary_category = max(categories.items(), key=lambda x: x[1])[0] if categories else 'uncategorized'
                category_distribution[primary_category] += 1
                
                results.append({
                    'feedback': feedback,
                    'sentiment': sentiment,
                    'categories': categories,
                    'primary_category': primary_category
                })
                
            # Normalize overall sentiment
            if self.feedback_data:
                count = len(self.feedback_data)
                for key in overall_sentiment:
                    overall_sentiment[key] /= count
            
            # Calculate positive/negative/neutral percentages
            sentiment_distribution = {
                'positive': sum(1 for r in results if r['sentiment'].get('compound', 0) >= 0.05) / max(1, len(results)),
                'negative': sum(1 for r in results if r['sentiment'].get('compound', 0) <= -0.05) / max(1, len(results)),
                'neutral': sum(1 for r in results if -0.05 < r['sentiment'].get('compound', 0) < 0.05) / max(1, len(results))
            }
            
            return {
                'results': results,
                'overall_sentiment': overall_sentiment,
                'sentiment_distribution': sentiment_distribution,
                'category_distribution': dict(category_distribution)
            }
    
    def generate_common_themes(self, top_n: int = 10) -> List[Tuple[str, int]]:
        """
        Generate common themes from all feedback
        
        Args:
            top_n: Number of top themes to return
            
        Returns:
            List of (theme, count) tuples
        """
        # Combine all text
        all_text = ' '.join([feedback.get('text', '') for feedback in self.feedback_data])
        
        # Get tokens
        tokens = self._preprocess_text(all_text)
        
        # Count frequency
        word_freq = Counter(tokens)
        
        # Get top N
        return word_freq.most_common(top_n)
    
    def version_comparison(self, version1: str, version2: str) -> Dict[str, Any]:
        """
        Compare feedback between two versions
        
        Args:
            version1: First version to compare
            version2: Second version to compare
            
        Returns:
            Dictionary with comparison results
        """
        if version1 not in self.version_data or version2 not in self.version_data:
            logger.error(f"One or both versions not found: {version1}, {version2}")
            return {}
            
        v1_feedback = self.version_data[version1]
        v2_feedback = self.version_data[version2]
        
        # Get average sentiment for each version
        v1_sentiment = {
            'pos': 0.0, 'neg': 0.0, 'neu': 0.0, 'compound': 0.0
        }
        v2_sentiment = {
            'pos': 0.0, 'neg': 0.0, 'neu': 0.0, 'compound': 0.0
        }
        
        for feedback in v1_feedback:
            sentiment = self._get_sentiment(feedback.get('text', ''))
            for key in v1_sentiment:
                v1_sentiment[key] += sentiment.get(key, 0.0)
        
        for feedback in v2_feedback:
            sentiment = self._get_sentiment(feedback.get('text', ''))
            for key in v2_sentiment:
                v2_sentiment[key] += sentiment.get(key, 0.0)
        
        # Normalize
        if v1_feedback:
            for key in v1_sentiment:
                v1_sentiment[key] /= len(v1_feedback)
        
        if v2_feedback:
            for key in v2_sentiment:
                v2_sentiment[key] /= len(v2_feedback)
        
        # Calculate category distributions
        v1_categories = defaultdict(int)
        v2_categories = defaultdict(int)
        
        for feedback in v1_feedback:
            categories = self._categorize_feedback(feedback.get('text', ''))
            primary_category = max(categories.items(), key=lambda x: x[1])[0] if categories else 'uncategorized'
            v1_categories[primary_category] += 1
            
        for feedback in v2_feedback:
            categories = self._categorize_feedback(feedback.get('text', ''))
            primary_category = max(categories.items(), key=lambda x: x[1])[0] if categories else 'uncategorized'
            v2_categories[primary_category] += 1
        
        return {
            'version1': {
                'version': version1,
                'feedback_count': len(v1_feedback),
                'sentiment': v1_sentiment,
                'categories': dict(v1_categories)
            },
            'version2': {
                'version': version2,
                'feedback_count': len(v2_feedback),
                'sentiment': v2_sentiment,
                'categories': dict(v2_categories)
            },
            'sentiment_diff': {
                key: v2_sentiment[key] - v1_sentiment[key] for key in v1_sentiment
            },
            'category_changes': {
                category: {
                    'v1_count': v1_categories.get(category, 0),
                    'v2_count': v2_categories.get(category, 0),
                    'change': v2_categories.get(category, 0) - v1_categories.get(category, 0)
                }
                for category in set(list(v1_categories.keys()) + list(v2_categories.keys()))
            }
        }
    
    def generate_report(self, output_format: str = 'dict') -> Any:
        """
        Generate a comprehensive feedback analysis report
        
        Args:
            output_format: Format of the report ('dict', 'json', 'html')
            
        Returns:
            Report in the specified format
        """
        if not self.feedback_data:
            logger.error("No feedback data to generate report")
            return None
            
        # Get overall analysis
        analysis = self.analyze_feedback()
        
        # Get common themes
        themes = self.generate_common_themes()
        
        # Get version breakdown if available
        versions = list(self.version_data.keys())
        version_breakdown = {}
        if len(versions) > 0:
            for version in versions:
                v_feedback = self.version_data[version]
                v_sentiments = [self._get_sentiment(f.get('text', ''))['compound'] for f in v_feedback]
                avg_sentiment = sum(v_sentiments) / len(v_sentiments) if v_sentiments else 0
                
                version_breakdown[version] = {
                    'count': len(v_feedback),
                    'avg_sentiment': avg_sentiment
                }
        
        # Create base report
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_feedback': len(self.feedback_data),
            'overall_sentiment': analysis['overall_sentiment'],
            'sentiment_distribution': analysis['sentiment_distribution'],
            'category_distribution': analysis['category_distribution'],
            'common_themes': dict(themes),
            'version_breakdown': version_breakdown
        }
        
        # Format report according to output_format
        if output_format == 'dict':
            return report
        elif output_format == 'json':
            return json.dumps(report, indent=2)
        elif output_format == 'html':
            # Simple HTML report
            html = f"""
            <html>
            <head>
                <title>Feedback Analysis Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1 {{ color: #333; }}
                    .section {{ margin-bottom: 20px; }}
                    .chart {{ width: 600px; height: 400px; }}
                    table {{ border-collapse: collapse; width: 100%; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                    tr:nth-child(even) {{ background-color: #f9f9f9; }}
                </style>
            </head>
            <body>
                <h1>Feedback Analysis Report</h1>
                <div class="section">
                    <h2>Overview</h2>
                    <p>Total Feedback: {len(self.feedback_data)}</p>
                    <p>Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                
                <div class="section">
                    <h2>Sentiment Analysis</h2>
                    <p>Overall Compound Score: {analysis['overall_sentiment']['compound']:.2f}</p>
                    <p>Positive: {analysis['sentiment_distribution']['positive']*100:.1f}%</p>
                    <p>Neutral: {analysis['sentiment_distribution']['neutral']*100:.1f}%</p>
                    <p>Negative: {analysis['sentiment_distribution']['negative']*100:.1f}%</p>
                </div>
                
                <div class="section">
                    <h2>Category Distribution</h2>
                    <table>
                        <tr>
                            <th>Category</th>
                            <th>Count</th>
                            <th>Percentage</th>
                        </tr>
            """
            
            total = sum(analysis['category_distribution'].values())
            for category, count in sorted(analysis['category_distribution'].items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total) * 100 if total > 0 else 0
                html += f"""
                        <tr>
                            <td>{category}</td>
                            <td>{count}</td>
                            <td>{percentage:.1f}%</td>
                        </tr>
                """
            
            html += """
                    </table>
                </div>
                
                <div class="section">
                    <h2>Common Themes</h2>
                    <table>
                        <tr>
                            <th>Theme</th>
                            <th>Frequency</th>
                        </tr>
            """
            
            for theme, count in themes:
                html += f"""
                        <tr>
                            <td>{theme}</td>
                            <td>{count}</td>
                        </tr>
                """
            
            html += """
                    </table>
                </div>
            """
            
            if version_breakdown:
                html += """
                <div class="section">
                    <h2>Version Breakdown</h2>
                    <table>
                        <tr>
                            <th>Version</th>
                            <th>Feedback Count</th>
                            <th>Average Sentiment</th>
                        </tr>
                """
                
                for version, data in sorted(version_breakdown.items()):
                    sentiment_class = ''
                    if data['avg_sentiment'] >= 0.05:
                        sentiment_class = 'style="color: green;"'
                    elif data['avg_sentiment'] <= -0.05:
                        sentiment_class = 'style="color: red;"'
                    
                    html += f"""
                        <tr>
                            <td>{version}</td>
                            <td>{data['count']}</td>
                            <td {sentiment_class}>{data['avg_sentiment']:.2f}</td>
                        </tr>
                    """
                
                html += """
                    </table>
                </div>
                """
            
            html += """
            </body>
            </html>
            """
            
            return html
        else:
            logger.error(f"Unsupported output format: {output_format}")
            return None
    
    def plot_sentiment_trend(self, timeframe: str = 'day') -> Optional[str]:
        """
        Plot sentiment trend over time
        
        Args:
            timeframe: Time aggregation ('day', 'week', 'month')
            
        Returns:
            Base64 encoded PNG image or None if plotting fails
        """
        try:
            # Ensure we have timestamp data
            timestamps = []
            sentiments = []
            
            for feedback in self.feedback_data:
                if 'timestamp' not in feedback:
                    continue
                    
                try:
                    timestamp = datetime.fromisoformat(feedback['timestamp'])
                    sentiment = self._get_sentiment(feedback.get('text', ''))['compound']
                    
                    timestamps.append(timestamp)
                    sentiments.append(sentiment)
                except (ValueError, TypeError):
                    continue
            
            if not timestamps:
                logger.error("No valid timestamp data for plotting")
                return None
                
            # Create DataFrame
            df = pd.DataFrame({
                'timestamp': timestamps,
                'sentiment': sentiments
            })
            
            # Set timestamp as index
            df.set_index('timestamp', inplace=True)
            
            # Resample based on timeframe
            if timeframe == 'day':
                df_resampled = df.resample('D').mean()
            elif timeframe == 'week':
                df_resampled = df.resample('W').mean()
            elif timeframe == 'month':
                df_resampled = df.resample('M').mean()
            else:
                logger.error(f"Unsupported timeframe: {timeframe}")
                return None
            
            # Plot
            plt.figure(figsize=(10, 6))
            plt.plot(df_resampled.index, df_resampled['sentiment'], marker='o')
            plt.axhline(y=0, color='r', linestyle='-', alpha=0.3)
            plt.fill_between(df_resampled.index, df_resampled['sentiment'], 0,
                             where=(df_resampled['sentiment'] >= 0), color='green', alpha=0.3)
            plt.fill_between(df_resampled.index, df_resampled['sentiment'], 0,
                             where=(df_resampled['sentiment'] < 0), color='red', alpha=0.3)
            plt.title(f'Sentiment Trend by {timeframe.capitalize()}')
            plt.ylabel('Compound Sentiment')
            plt.grid(True, linestyle='--', alpha=0.7)
            
            # Save to bytes buffer
            buf = io.BytesIO()
            plt.savefig(buf, format='png', dpi=100)
            buf.seek(0)
            
            # Encode as base64
            img_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
            plt.close()
            
            return img_base64
        except Exception as e:
            logger.error(f"Error plotting sentiment trend: {str(e)}")
            return None
    
    def plot_category_distribution(self) -> Optional[str]:
        """
        Plot category distribution
        
        Returns:
            Base64 encoded PNG image or None if plotting fails
        """
        try:
            if not self.feedback_data:
                logger.error("No feedback data for plotting")
                return None
                
            # Get category distribution
            analysis = self.analyze_feedback()
            category_dist = analysis['category_distribution']
            
            categories = list(category_dist.keys())
            counts = list(category_dist.values())
            
            # Create pie chart
            plt.figure(figsize=(10, 8))
            plt.pie(counts, labels=categories, autopct='%1.1f%%', shadow=True, startangle=140)
            plt.axis('equal')
            plt.title('Feedback Category Distribution')
            
            # Save to bytes buffer
            buf = io.BytesIO()
            plt.savefig(buf, format='png', dpi=100)
            buf.seek(0)
            
            # Encode as base64
            img_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
            plt.close()
            
            return img_base64
        except Exception as e:
            logger.error(f"Error plotting category distribution: {str(e)}")
            return None
    
    def export_data(self, file_path: str, format_type: str = 'csv') -> bool:
        """
        Export analyzed feedback data
        
        Args:
            file_path: Path to save the exported data
            format_type: Format to export ('csv', 'json')
            
        Returns:
            True if exported successfully
        """
        try:
            # Analyze all feedback
            analysis = self.analyze_feedback()
            
            # Create export data
            export_data = []
            for result in analysis['results']:
                feedback = result['feedback']
                sentiment = result['sentiment']
                categories = result['categories']
                
                export_row = {
                    'id': feedback.get('id', ''),
                    'user_id': feedback.get('user_id', ''),
                    'timestamp': feedback.get('timestamp', ''),
                    'version': feedback.get('version', ''),
                    'text': feedback.get('text', ''),
                    'sentiment_compound': sentiment.get('compound', 0),
                    'sentiment_positive': sentiment.get('pos', 0),
                    'sentiment_negative': sentiment.get('neg', 0),
                    'sentiment_neutral': sentiment.get('neu', 0),
                    'primary_category': result['primary_category']
                }
                
                # Add category scores
                for category, score in categories.items():
                    export_row[f'category_{category}'] = score
                
                export_data.append(export_row)
            
            # Export based on format
            if format_type == 'csv':
                df = pd.DataFrame(export_data)
                df.to_csv(file_path, index=False)
            elif format_type == 'json':
                with open(file_path, 'w') as f:
                    json.dump(export_data, f, indent=2)
            else:
                logger.error(f"Unsupported export format: {format_type}")
                return False
                
            logger.info(f"Exported {len(export_data)} feedback entries to {file_path}")
            return True
        except Exception as e:
            logger.error(f"Error exporting data: {str(e)}")
            return False
    
    def clear_data(self) -> None:
        """Clear all loaded feedback data"""
        self.feedback_data = []
        self.version_data = {}
        logger.info("Feedback data cleared")

# Helper functions
def create_feedback_analyzer() -> FeedbackAnalyzer:
    """Create and return a feedback analyzer instance"""
    return FeedbackAnalyzer()

def process_feedback_batch(feedback_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Process a batch of feedback and return analysis
    
    Args:
        feedback_list: List of feedback dictionaries
        
    Returns:
        Dictionary with analysis results
    """
    analyzer = FeedbackAnalyzer()
    
    for feedback in feedback_list:
        analyzer.add_feedback(feedback)
    
    return analyzer.analyze_feedback() 