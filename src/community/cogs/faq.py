#!/usr/bin/env python3
"""
FAQ Cog for ARP Guard Discord Bot

This cog handles automated responses to frequently asked questions
and provides quick access to documentation.
"""

import discord
from discord.ext import commands
import logging
import json
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class FAQCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.faq_data = self._load_faq_data()
        self.docs_links = self._load_docs_links()
    
    def _load_faq_data(self) -> Dict[str, Dict]:
        """Load FAQ data from JSON file."""
        try:
            with open("src/community/data/faq.json", "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load FAQ data: {str(e)}")
            return {}
    
    def _load_docs_links(self) -> Dict[str, str]:
        """Load documentation links from JSON file."""
        try:
            with open("src/community/data/docs_links.json", "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load docs links: {str(e)}")
            return {}
    
    @commands.command(name="faq")
    async def show_faq(self, ctx, topic: Optional[str] = None):
        """Show FAQ topics or specific FAQ entry."""
        if not topic:
            # Show all FAQ topics
            embed = discord.Embed(
                title="ARP Guard FAQ Topics",
                description="Use !faq <topic> to see details about a specific topic.",
                color=discord.Color.blue()
            )
            
            for topic_name, data in self.faq_data.items():
                embed.add_field(
                    name=topic_name,
                    value=data["short_description"],
                    inline=False
                )
            
            await ctx.send(embed=embed)
        else:
            # Show specific FAQ entry
            topic = topic.lower()
            if topic in self.faq_data:
                data = self.faq_data[topic]
                embed = discord.Embed(
                    title=f"FAQ: {topic.title()}",
                    description=data["description"],
                    color=discord.Color.green()
                )
                
                if "example" in data:
                    embed.add_field(
                        name="Example",
                        value=data["example"],
                        inline=False
                    )
                
                if topic in self.docs_links:
                    embed.add_field(
                        name="Documentation",
                        value=f"[Read more]({self.docs_links[topic]})",
                        inline=False
                    )
                
                await ctx.send(embed=embed)
            else:
                await ctx.send(f"Topic '{topic}' not found in FAQ. Use !faq to see available topics.")
    
    @commands.command(name="docs")
    async def show_docs(self, ctx, section: Optional[str] = None):
        """Show documentation links or specific section."""
        if not section:
            # Show all documentation sections
            embed = discord.Embed(
                title="ARP Guard Documentation",
                description="Use !docs <section> to get a direct link to a specific section.",
                color=discord.Color.blue()
            )
            
            for section_name, link in self.docs_links.items():
                embed.add_field(
                    name=section_name.title(),
                    value=f"[View Documentation]({link})",
                    inline=False
                )
            
            await ctx.send(embed=embed)
        else:
            # Show specific documentation section
            section = section.lower()
            if section in self.docs_links:
                await ctx.send(f"Documentation for {section}: {self.docs_links[section]}")
            else:
                await ctx.send(f"Section '{section}' not found. Use !docs to see available sections.")
    
    @commands.command(name="search")
    async def search_docs(self, ctx, *, query: str):
        """Search the documentation."""
        # This would typically call an external search API
        # For now, we'll do a simple keyword match
        results = []
        query = query.lower()
        
        for topic, data in self.faq_data.items():
            if query in topic.lower() or query in data["description"].lower():
                results.append((topic, data["short_description"]))
        
        if results:
            embed = discord.Embed(
                title=f"Search Results for '{query}'",
                color=discord.Color.blue()
            )
            
            for topic, desc in results[:5]:  # Limit to 5 results
                embed.add_field(
                    name=topic.title(),
                    value=desc,
                    inline=False
                )
            
            if len(results) > 5:
                embed.set_footer(text=f"Showing 5 of {len(results)} results. Try a more specific search.")
            
            await ctx.send(embed=embed)
        else:
            await ctx.send(f"No results found for '{query}'. Try a different search term.")
    
    @commands.command(name="updatefaq")
    @commands.has_role("Moderator")
    async def update_faq(self, ctx, topic: str, *, content: str):
        """Update FAQ content (Moderators only)."""
        try:
            # Parse content (format: description|short_description|example)
            parts = content.split("|")
            if len(parts) < 2:
                await ctx.send("Invalid format. Use: description|short_description|example")
                return
            
            self.faq_data[topic.lower()] = {
                "description": parts[0].strip(),
                "short_description": parts[1].strip(),
                "example": parts[2].strip() if len(parts) > 2 else None
            }
            
            # Save updated FAQ data
            with open("src/community/data/faq.json", "w") as f:
                json.dump(self.faq_data, f, indent=2)
            
            await ctx.send(f"FAQ topic '{topic}' updated successfully.")
            
        except Exception as e:
            logger.error(f"Failed to update FAQ: {str(e)}")
            await ctx.send("Failed to update FAQ. Check logs for details.")

def setup(bot):
    """Add the cog to the bot."""
    bot.add_cog(FAQCog(bot)) 