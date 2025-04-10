#!/usr/bin/env python3
"""
Discord Bot for ARP Guard Community Support

This bot provides automated support, community engagement, and information
sharing for ARP Guard users.
"""

import discord
from discord.ext import commands
import logging
import json
from typing import Dict, List
import asyncio
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ARPGuardBot(commands.Bot):
    def __init__(self, config_path: str = "discord_config.json"):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.members = True
        
        super().__init__(command_prefix='!', intents=intents)
        
        self.config = self._load_config(config_path)
        self.faq_data = self._load_faq()
        self.support_channels = self.config.get("support_channels", [])
        self.announcement_channel = self.config.get("announcement_channel")
        
        # Load cogs
        self.load_extension("src.community.cogs.support")
        self.load_extension("src.community.cogs.announcements")
        self.load_extension("src.community.cogs.faq")
        
    def _load_config(self, config_path: str) -> Dict:
        """Load bot configuration from file."""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Config file {config_path} not found. Using defaults.")
            return {
                "support_channels": [],
                "announcement_channel": None,
                "moderator_roles": ["Moderator", "Admin"],
                "welcome_message": "Welcome to the ARP Guard community!",
                "rules_channel": "rules"
            }
    
    def _load_faq(self) -> Dict:
        """Load FAQ data from file."""
        try:
            with open("faq.json", 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning("FAQ file not found. Using defaults.")
            return {
                "general": [
                    {
                        "question": "What is ARP Guard?",
                        "answer": "ARP Guard is a network security tool that detects and prevents ARP spoofing attacks."
                    }
                ],
                "installation": [],
                "troubleshooting": []
            }
    
    async def on_ready(self):
        """Called when the bot is ready."""
        logger.info(f'Logged in as {self.user.name} ({self.user.id})')
        logger.info('------')
        
        # Set bot status
        await self.change_presence(
            activity=discord.Activity(
                type=discord.ActivityType.watching,
                name="for ARP spoofing attacks"
            )
        )
    
    async def on_member_join(self, member):
        """Called when a new member joins the server."""
        # Send welcome message
        welcome_channel = discord.utils.get(member.guild.channels, name="welcome")
        if welcome_channel:
            await welcome_channel.send(
                f"{member.mention} {self.config['welcome_message']}\n"
                f"Please read the rules in #{self.config['rules_channel']}"
            )
        
        # Assign default role
        default_role = discord.utils.get(member.guild.roles, name="Community")
        if default_role:
            await member.add_roles(default_role)
    
    async def on_message(self, message):
        """Called when a message is sent in any channel."""
        # Ignore messages from bots
        if message.author.bot:
            return
        
        # Process commands
        await self.process_commands(message)
        
        # Check for support requests
        if message.channel.id in self.support_channels:
            await self._handle_support_message(message)

    async def _handle_support_message(self, message):
        """Handle messages in support channels."""
        # Check for common issues
        content = message.content.lower()
        if "error" in content or "help" in content:
            # Create support ticket
            ticket_channel = await self._create_support_ticket(message)
            if ticket_channel:
                await message.channel.send(
                    f"{message.author.mention} I've created a support ticket for you in {ticket_channel.mention}"
                )

    async def _create_support_ticket(self, message) -> Optional[discord.TextChannel]:
        """Create a support ticket channel for a user."""
        try:
            # Get the support category
            category = discord.utils.get(message.guild.categories, name="Support Tickets")
            if not category:
                category = await message.guild.create_category("Support Tickets")
            
            # Create ticket channel
            ticket_name = f"ticket-{message.author.name}-{datetime.now().strftime('%Y%m%d')}"
            ticket_channel = await message.guild.create_text_channel(
                ticket_name,
                category=category,
                topic=f"Support ticket for {message.author.name}"
            )
            
            # Set permissions
            await ticket_channel.set_permissions(
                message.guild.default_role,
                read_messages=False
            )
            await ticket_channel.set_permissions(
                message.author,
                read_messages=True,
                send_messages=True
            )
            
            # Add moderators
            for role_name in self.config["moderator_roles"]:
                role = discord.utils.get(message.guild.roles, name=role_name)
                if role:
                    await ticket_channel.set_permissions(
                        role,
                        read_messages=True,
                        send_messages=True
                    )
            
            # Send initial message
            await ticket_channel.send(
                f"{message.author.mention} Welcome to your support ticket!\n"
                f"Please describe your issue in detail and a moderator will assist you shortly."
            )
            
            return ticket_channel
            
        except Exception as e:
            logger.error(f"Failed to create support ticket: {str(e)}")
            return None

def main():
    """Start the Discord bot."""
    bot = ARPGuardBot()
    bot.run(bot.config["token"])

if __name__ == "__main__":
    main() 