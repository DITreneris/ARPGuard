import discord
from discord.ext import commands
import json
import os
from datetime import datetime
from typing import Dict, List, Optional
import asyncio

class CommunityCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.polls_file = 'src/community/data/polls.json'
        self.announcements_file = 'src/community/data/announcements.json'
        self.stats_file = 'src/community/data/community_stats.json'
        self.polls = self._load_polls()
        self.announcements = self._load_announcements()
        self.stats = self._load_stats()
        self.announcement_channel_id = None  # Set this in setup

    def _load_polls(self) -> Dict:
        """Load polls from JSON file."""
        try:
            with open(self.polls_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def _load_announcements(self) -> Dict:
        """Load announcements from JSON file."""
        try:
            with open(self.announcements_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def _load_stats(self) -> Dict:
        """Load community statistics from JSON file."""
        try:
            with open(self.stats_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {
                "total_messages": 0,
                "active_users": {},
                "polls_created": 0,
                "announcements_made": 0
            }

    def _save_polls(self):
        """Save polls to JSON file."""
        os.makedirs(os.path.dirname(self.polls_file), exist_ok=True)
        with open(self.polls_file, 'w') as f:
            json.dump(self.polls, f, indent=4)

    def _save_announcements(self):
        """Save announcements to JSON file."""
        os.makedirs(os.path.dirname(self.announcements_file), exist_ok=True)
        with open(self.announcements_file, 'w') as f:
            json.dump(self.announcements, f, indent=4)

    def _save_stats(self):
        """Save community statistics to JSON file."""
        os.makedirs(os.path.dirname(self.stats_file), exist_ok=True)
        with open(self.stats_file, 'w') as f:
            json.dump(self.stats, f, indent=4)

    @commands.command(name='poll')
    async def create_poll(self, ctx, question: str, *options: str):
        """Create a new poll."""
        if len(options) < 2:
            await ctx.send("Please provide at least 2 options for the poll.")
            return

        poll_id = f"POLL-{len(self.polls) + 1:04d}"
        poll_data = {
            "id": poll_id,
            "question": question,
            "options": {opt: 0 for opt in options},
            "creator_id": str(ctx.author.id),
            "created_at": datetime.utcnow().isoformat(),
            "voters": []
        }

        self.polls[poll_id] = poll_data
        self._save_polls()
        self.stats["polls_created"] += 1
        self._save_stats()

        # Create poll embed
        embed = discord.Embed(
            title=f"Poll: {question}",
            description="React with the corresponding emoji to vote!",
            color=discord.Color.blue()
        )

        # Add options with emojis
        emojis = ["1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟"]
        for i, option in enumerate(options):
            if i < len(emojis):
                embed.add_field(name=f"{emojis[i]} {option}", value="0 votes", inline=False)

        poll_message = await ctx.send(embed=embed)

        # Add reactions
        for i in range(len(options)):
            if i < len(emojis):
                await poll_message.add_reaction(emojis[i])

    @commands.command(name='announce')
    @commands.has_permissions(administrator=True)
    async def make_announcement(self, ctx, *, message: str):
        """Make an announcement (Admin only)."""
        if not self.announcement_channel_id:
            await ctx.send("Announcement channel not configured.")
            return

        announcement_id = f"ANN-{len(self.announcements) + 1:04d}"
        announcement_data = {
            "id": announcement_id,
            "message": message,
            "author_id": str(ctx.author.id),
            "created_at": datetime.utcnow().isoformat()
        }

        self.announcements[announcement_id] = announcement_data
        self._save_announcements()
        self.stats["announcements_made"] += 1
        self._save_stats()

        # Create announcement embed
        embed = discord.Embed(
            title="📢 New Announcement",
            description=message,
            color=discord.Color.gold()
        )
        embed.set_footer(text=f"Announced by {ctx.author.name}")

        # Send to announcement channel
        announcement_channel = self.bot.get_channel(self.announcement_channel_id)
        if announcement_channel:
            await announcement_channel.send("@everyone", embed=embed)
            await ctx.send("Announcement sent successfully!")

    @commands.command(name='stats')
    async def show_stats(self, ctx):
        """Show community statistics."""
        embed = discord.Embed(
            title="Community Statistics",
            color=discord.Color.green()
        )

        # Add statistics
        embed.add_field(
            name="Total Messages",
            value=str(self.stats["total_messages"]),
            inline=True
        )
        embed.add_field(
            name="Polls Created",
            value=str(self.stats["polls_created"]),
            inline=True
        )
        embed.add_field(
            name="Announcements Made",
            value=str(self.stats["announcements_made"]),
            inline=True
        )

        # Add top active users
        active_users = sorted(
            self.stats["active_users"].items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]

        if active_users:
            top_users = "\n".join([
                f"<@{user_id}>: {count} messages"
                for user_id, count in active_users
            ])
            embed.add_field(
                name="Top Active Users",
                value=top_users,
                inline=False
            )

        await ctx.send(embed=embed)

    @commands.Cog.listener()
    async def on_message(self, message):
        """Track message statistics."""
        if message.author.bot:
            return

        # Update total messages
        self.stats["total_messages"] += 1

        # Update user activity
        user_id = str(message.author.id)
        self.stats["active_users"][user_id] = self.stats["active_users"].get(user_id, 0) + 1

        # Save stats periodically
        if self.stats["total_messages"] % 10 == 0:
            self._save_stats()

    @commands.Cog.listener()
    async def on_raw_reaction_add(self, payload):
        """Handle poll votes."""
        if payload.user_id == self.bot.user.id:
            return

        # Find the poll message
        channel = self.bot.get_channel(payload.channel_id)
        message = await channel.fetch_message(payload.message_id)

        # Check if it's a poll message
        for poll_id, poll_data in self.polls.items():
            if message.embeds and message.embeds[0].title.startswith("Poll:"):
                # Update poll votes
                emojis = ["1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟"]
                if payload.emoji.name in emojis:
                    option_index = emojis.index(payload.emoji.name)
                    if option_index < len(poll_data["options"]):
                        option = list(poll_data["options"].keys())[option_index]
                        poll_data["options"][option] += 1
                        self._save_polls()

                        # Update embed
                        embed = message.embeds[0]
                        for i, (option, votes) in enumerate(poll_data["options"].items()):
                            embed.set_field_at(
                                i,
                                name=f"{emojis[i]} {option}",
                                value=f"{votes} votes",
                                inline=False
                            )
                        await message.edit(embed=embed)

def setup(bot):
    cog = CommunityCog(bot)
    # Set the announcement channel ID (replace with your actual channel ID)
    cog.announcement_channel_id = 123456789  # Replace with your channel ID
    bot.add_cog(cog) 