#!/usr/bin/env python3
"""
Support Cog for ARP Guard Discord Bot

This cog handles support ticket management and automated responses
for the ARP Guard community Discord server.
"""

import discord
from discord.ext import commands
import logging
from typing import Optional
import json
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class SupportCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.ticket_timeout = timedelta(hours=48)  # Close tickets after 48 hours of inactivity
        self.ticket_archive = {}
        
    @commands.command(name="ticket")
    async def create_ticket(self, ctx, *, reason: Optional[str] = None):
        """Create a support ticket."""
        # Check if user already has an open ticket
        if self._has_open_ticket(ctx.author):
            await ctx.send("You already have an open support ticket.")
            return
        
        # Create ticket channel
        ticket_channel = await self._create_ticket_channel(ctx, reason)
        if ticket_channel:
            await ctx.send(f"Created support ticket: {ticket_channel.mention}")
    
    @commands.command(name="close")
    @commands.has_role("Moderator")
    async def close_ticket(self, ctx):
        """Close a support ticket."""
        if not self._is_ticket_channel(ctx.channel):
            await ctx.send("This command can only be used in ticket channels.")
            return
        
        # Archive ticket
        await self._archive_ticket(ctx.channel)
        
        # Send closing message
        await ctx.send("This ticket will be closed in 10 seconds.")
        await asyncio.sleep(10)
        
        # Delete channel
        await ctx.channel.delete()
    
    @commands.command(name="add")
    @commands.has_role("Moderator")
    async def add_to_ticket(self, ctx, member: discord.Member):
        """Add a user to the current ticket."""
        if not self._is_ticket_channel(ctx.channel):
            await ctx.send("This command can only be used in ticket channels.")
            return
        
        # Add user to ticket
        await ctx.channel.set_permissions(
            member,
            read_messages=True,
            send_messages=True
        )
        await ctx.send(f"Added {member.mention} to the ticket.")
    
    @commands.command(name="remove")
    @commands.has_role("Moderator")
    async def remove_from_ticket(self, ctx, member: discord.Member):
        """Remove a user from the current ticket."""
        if not self._is_ticket_channel(ctx.channel):
            await ctx.send("This command can only be used in ticket channels.")
            return
        
        # Remove user from ticket
        await ctx.channel.set_permissions(
            member,
            read_messages=False,
            send_messages=False
        )
        await ctx.send(f"Removed {member.mention} from the ticket.")
    
    @commands.command(name="tickets")
    @commands.has_role("Moderator")
    async def list_tickets(self, ctx):
        """List all open support tickets."""
        tickets = self._get_open_tickets()
        if not tickets:
            await ctx.send("No open tickets.")
            return
        
        embed = discord.Embed(
            title="Open Support Tickets",
            color=discord.Color.blue()
        )
        
        for ticket in tickets:
            embed.add_field(
                name=ticket.name,
                value=f"Created by: {ticket.topic}\nStatus: Open",
                inline=False
            )
        
        await ctx.send(embed=embed)
    
    def _has_open_ticket(self, member: discord.Member) -> bool:
        """Check if a member has an open ticket."""
        for channel in member.guild.channels:
            if self._is_ticket_channel(channel) and channel.topic == f"Support ticket for {member.name}":
                return True
        return False
    
    def _is_ticket_channel(self, channel: discord.TextChannel) -> bool:
        """Check if a channel is a ticket channel."""
        return channel.category and channel.category.name == "Support Tickets"
    
    def _get_open_tickets(self) -> List[discord.TextChannel]:
        """Get all open support tickets."""
        return [
            channel for channel in self.bot.get_all_channels()
            if self._is_ticket_channel(channel)
        ]
    
    async def _create_ticket_channel(self, ctx, reason: Optional[str]) -> Optional[discord.TextChannel]:
        """Create a support ticket channel."""
        try:
            # Get or create support category
            category = discord.utils.get(ctx.guild.categories, name="Support Tickets")
            if not category:
                category = await ctx.guild.create_category("Support Tickets")
            
            # Create ticket channel
            ticket_name = f"ticket-{ctx.author.name}-{datetime.now().strftime('%Y%m%d')}"
            ticket_channel = await ctx.guild.create_text_channel(
                ticket_name,
                category=category,
                topic=f"Support ticket for {ctx.author.name}"
            )
            
            # Set permissions
            await ticket_channel.set_permissions(
                ctx.guild.default_role,
                read_messages=False
            )
            await ticket_channel.set_permissions(
                ctx.author,
                read_messages=True,
                send_messages=True
            )
            
            # Add moderators
            for role_name in self.bot.config["moderator_roles"]:
                role = discord.utils.get(ctx.guild.roles, name=role_name)
                if role:
                    await ticket_channel.set_permissions(
                        role,
                        read_messages=True,
                        send_messages=True
                    )
            
            # Send initial message
            embed = discord.Embed(
                title="Support Ticket",
                description="A moderator will assist you shortly.",
                color=discord.Color.green()
            )
            
            if reason:
                embed.add_field(name="Reason", value=reason, inline=False)
            
            embed.add_field(
                name="Available Commands",
                value="!close - Close this ticket (Moderators only)\n"
                      "!add @user - Add a user to this ticket\n"
                      "!remove @user - Remove a user from this ticket",
                inline=False
            )
            
            await ticket_channel.send(embed=embed)
            
            return ticket_channel
            
        except Exception as e:
            logger.error(f"Failed to create ticket channel: {str(e)}")
            return None
    
    async def _archive_ticket(self, channel: discord.TextChannel):
        """Archive a support ticket."""
        try:
            # Get ticket messages
            messages = []
            async for message in channel.history(limit=None):
                messages.append({
                    "author": str(message.author),
                    "content": message.content,
                    "timestamp": message.created_at.isoformat(),
                    "attachments": [a.url for a in message.attachments]
                })
            
            # Store in archive
            self.ticket_archive[channel.id] = {
                "name": channel.name,
                "topic": channel.topic,
                "created_at": channel.created_at.isoformat(),
                "closed_at": datetime.now().isoformat(),
                "messages": messages
            }
            
            # Save archive to file
            with open("ticket_archive.json", "w") as f:
                json.dump(self.ticket_archive, f, indent=2)
            
        except Exception as e:
            logger.error(f"Failed to archive ticket: {str(e)}")

def setup(bot):
    """Add the cog to the bot."""
    bot.add_cog(SupportCog(bot)) 