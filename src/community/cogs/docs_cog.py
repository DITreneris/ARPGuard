import discord
from discord.ext import commands
import json
import os
from typing import Dict, List, Optional
import re
from datetime import datetime
import aiohttp
import asyncio

class DocumentationCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.docs_dir = 'src/community/docs'
        self.docs_index = self._load_docs_index()
        self.versions = self._get_available_versions()
        self.search_cache = {}

    def _load_docs_index(self) -> Dict:
        """Load documentation index from JSON file."""
        try:
            with open(os.path.join(self.docs_dir, 'index.json'), 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def _get_available_versions(self) -> List[str]:
        """Get list of available documentation versions."""
        versions = []
        for item in os.listdir(self.docs_dir):
            if os.path.isdir(os.path.join(self.docs_dir, item)) and re.match(r'^\d+\.\d+\.\d+$', item):
                versions.append(item)
        return sorted(versions, reverse=True)

    def _get_doc_content(self, version: str, path: str) -> Optional[str]:
        """Get documentation content for a specific version and path."""
        try:
            with open(os.path.join(self.docs_dir, version, f"{path}.md"), 'r') as f:
                return f.read()
        except FileNotFoundError:
            return None

    def _create_search_index(self, version: str):
        """Create search index for documentation version."""
        if version in self.search_cache:
            return

        search_index = {}
        for section, data in self.docs_index.items():
            content = self._get_doc_content(version, data['path'])
            if content:
                # Simple word-based indexing
                words = re.findall(r'\w+', content.lower())
                for word in words:
                    if word not in search_index:
                        search_index[word] = []
                    if section not in search_index[word]:
                        search_index[word].append(section)

        self.search_cache[version] = search_index

    @commands.command(name='docs')
    async def show_docs(self, ctx, section: Optional[str] = None, version: Optional[str] = None):
        """Show documentation section or list available sections."""
        if not version:
            version = self.versions[0]  # Use latest version by default

        if version not in self.versions:
            await ctx.send(f"Version {version} not found. Available versions: {', '.join(self.versions)}")
            return

        if not section:
            # Show available sections
            embed = discord.Embed(
                title=f"ARP Guard Documentation (v{version})",
                description="Available documentation sections:",
                color=discord.Color.blue()
            )

            for section_name, data in self.docs_index.items():
                embed.add_field(
                    name=section_name,
                    value=data['description'],
                    inline=False
                )

            await ctx.send(embed=embed)
            return

        # Show specific section
        section = section.lower()
        if section not in self.docs_index:
            await ctx.send(f"Section '{section}' not found. Use `!docs` to see available sections.")
            return

        content = self._get_doc_content(version, self.docs_index[section]['path'])
        if not content:
            await ctx.send(f"Documentation for section '{section}' not found.")
            return

        # Split content into chunks if too long
        chunks = [content[i:i+1024] for i in range(0, len(content), 1024)]
        
        for i, chunk in enumerate(chunks):
            embed = discord.Embed(
                title=f"Documentation: {section.capitalize()} (v{version})",
                description=chunk,
                color=discord.Color.green()
            )
            if i == 0:
                embed.set_footer(text=f"Page {i+1}/{len(chunks)}")
            await ctx.send(embed=embed)

    @commands.command(name='searchdocs')
    async def search_docs(self, ctx, query: str, version: Optional[str] = None):
        """Search documentation for specific terms."""
        if not version:
            version = self.versions[0]  # Use latest version by default

        if version not in self.versions:
            await ctx.send(f"Version {version} not found. Available versions: {', '.join(self.versions)}")
            return

        # Create search index if not exists
        self._create_search_index(version)

        # Search for terms
        query_terms = re.findall(r'\w+', query.lower())
        results = set()

        for term in query_terms:
            if term in self.search_cache[version]:
                results.update(self.search_cache[version][term])

        if not results:
            await ctx.send(f"No results found for '{query}' in version {version}.")
            return

        # Create results embed
        embed = discord.Embed(
            title=f"Search Results for '{query}' (v{version})",
            description="Found in the following sections:",
            color=discord.Color.blue()
        )

        for section in sorted(results):
            embed.add_field(
                name=section,
                value=self.docs_index[section]['description'],
                inline=False
            )

        await ctx.send(embed=embed)

    @commands.command(name='docsupdate')
    @commands.has_permissions(administrator=True)
    async def update_docs(self, ctx, version: str, section: str, *, content: str):
        """Update documentation content (Admin only)."""
        if not ctx.author.guild_permissions.administrator:
            await ctx.send("You don't have permission to use this command.")
            return

        if section.lower() not in self.docs_index:
            await ctx.send(f"Section '{section}' not found in documentation index.")
            return

        # Create version directory if it doesn't exist
        version_dir = os.path.join(self.docs_dir, version)
        os.makedirs(version_dir, exist_ok=True)

        # Save documentation content
        doc_path = os.path.join(version_dir, f"{self.docs_index[section.lower()]['path']}.md")
        with open(doc_path, 'w') as f:
            f.write(content)

        # Clear search cache for this version
        if version in self.search_cache:
            del self.search_cache[version]

        await ctx.send(f"Documentation for section '{section}' updated successfully in version {version}.")

    @commands.command(name='docsversion')
    async def show_version(self, ctx, version: Optional[str] = None):
        """Show documentation version or list available versions."""
        if not version:
            embed = discord.Embed(
                title="Available Documentation Versions",
                description="\n".join([
                    f"• v{ver} {'(Latest)' if i == 0 else ''}"
                    for i, ver in enumerate(self.versions)
                ]),
                color=discord.Color.blue()
            )
            await ctx.send(embed=embed)
            return

        if version not in self.versions:
            await ctx.send(f"Version {version} not found. Available versions: {', '.join(self.versions)}")
            return

        # Show version-specific information
        version_dir = os.path.join(self.docs_dir, version)
        last_updated = datetime.fromtimestamp(
            os.path.getmtime(os.path.join(version_dir, 'index.json'))
        ).strftime('%Y-%m-%d %H:%M:%S')

        embed = discord.Embed(
            title=f"Documentation Version {version}",
            color=discord.Color.green()
        )
        embed.add_field(name="Last Updated", value=last_updated, inline=False)
        embed.add_field(
            name="Available Sections",
            value="\n".join([f"• {section}" for section in self.docs_index.keys()]),
            inline=False
        )

        await ctx.send(embed=embed)

def setup(bot):
    bot.add_cog(DocumentationCog(bot)) 