import discord
from discord.ext import commands
import json
import os
from datetime import datetime
from typing import Dict, Optional

class SupportCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.tickets_file = 'src/community/data/support_tickets.json'
        self.tickets = self._load_tickets()
        self.support_channel_id = None  # Set this in setup

    def _load_tickets(self) -> Dict:
        """Load support tickets from JSON file."""
        try:
            with open(self.tickets_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def _save_tickets(self):
        """Save support tickets to JSON file."""
        os.makedirs(os.path.dirname(self.tickets_file), exist_ok=True)
        with open(self.tickets_file, 'w') as f:
            json.dump(self.tickets, f, indent=4)

    @commands.command(name='ticket')
    async def create_ticket(self, ctx, *, description: str):
        """Create a new support ticket."""
        ticket_id = f"TICKET-{len(self.tickets) + 1:04d}"
        
        # Create ticket data
        ticket_data = {
            "id": ticket_id,
            "user_id": str(ctx.author.id),
            "username": str(ctx.author),
            "description": description,
            "status": "open",
            "created_at": datetime.utcnow().isoformat(),
            "responses": []
        }

        # Save ticket
        self.tickets[ticket_id] = ticket_data
        self._save_tickets()

        # Create embed
        embed = discord.Embed(
            title=f"Support Ticket Created: {ticket_id}",
            description=f"**Description:**\n{description}",
            color=discord.Color.green()
        )
        embed.add_field(name="Status", value="Open", inline=True)
        embed.add_field(name="Created By", value=ctx.author.mention, inline=True)
        embed.set_footer(text=f"Use !respond {ticket_id} to respond to this ticket")

        # Send confirmation
        await ctx.send(embed=embed)

        # Send to support channel if configured
        if self.support_channel_id:
            support_channel = self.bot.get_channel(self.support_channel_id)
            if support_channel:
                await support_channel.send(embed=embed)

    @commands.command(name='respond')
    @commands.has_permissions(administrator=True)
    async def respond_to_ticket(self, ctx, ticket_id: str, *, response: str):
        """Respond to a support ticket (Admin only)."""
        ticket_id = ticket_id.upper()
        if ticket_id not in self.tickets:
            await ctx.send(f"Ticket {ticket_id} not found.")
            return

        ticket = self.tickets[ticket_id]
        ticket["responses"].append({
            "responder_id": str(ctx.author.id),
            "responder_name": str(ctx.author),
            "response": response,
            "timestamp": datetime.utcnow().isoformat()
        })

        self._save_tickets()

        # Create embed
        embed = discord.Embed(
            title=f"Response to Ticket {ticket_id}",
            description=f"**Response:**\n{response}",
            color=discord.Color.blue()
        )
        embed.add_field(name="Responded By", value=ctx.author.mention, inline=True)
        embed.add_field(name="Status", value=ticket["status"], inline=True)

        # Send response
        await ctx.send(embed=embed)

        # Notify ticket creator
        try:
            user = await self.bot.fetch_user(int(ticket["user_id"]))
            await user.send(embed=embed)
        except discord.NotFound:
            await ctx.send("Could not notify ticket creator (user not found).")

    @commands.command(name='ticketstatus')
    async def ticket_status(self, ctx, ticket_id: str):
        """Check the status of a support ticket."""
        ticket_id = ticket_id.upper()
        if ticket_id not in self.tickets:
            await ctx.send(f"Ticket {ticket_id} not found.")
            return

        ticket = self.tickets[ticket_id]
        embed = discord.Embed(
            title=f"Ticket Status: {ticket_id}",
            description=f"**Description:**\n{ticket['description']}",
            color=discord.Color.blue()
        )
        embed.add_field(name="Status", value=ticket["status"], inline=True)
        embed.add_field(name="Created By", value=f"<@{ticket['user_id']}>", inline=True)
        embed.add_field(name="Created At", value=ticket["created_at"], inline=False)

        if ticket["responses"]:
            responses_text = "\n\n".join([
                f"**{r['responder_name']}** ({r['timestamp']}):\n{r['response']}"
                for r in ticket["responses"]
            ])
            embed.add_field(name="Responses", value=responses_text, inline=False)

        await ctx.send(embed=embed)

    @commands.command(name='closeticket')
    @commands.has_permissions(administrator=True)
    async def close_ticket(self, ctx, ticket_id: str):
        """Close a support ticket (Admin only)."""
        ticket_id = ticket_id.upper()
        if ticket_id not in self.tickets:
            await ctx.send(f"Ticket {ticket_id} not found.")
            return

        ticket = self.tickets[ticket_id]
        ticket["status"] = "closed"
        self._save_tickets()

        embed = discord.Embed(
            title=f"Ticket Closed: {ticket_id}",
            description="This ticket has been closed.",
            color=discord.Color.red()
        )
        await ctx.send(embed=embed)

        # Notify ticket creator
        try:
            user = await self.bot.fetch_user(int(ticket["user_id"]))
            await user.send(embed=embed)
        except discord.NotFound:
            await ctx.send("Could not notify ticket creator (user not found).")

def setup(bot):
    cog = SupportCog(bot)
    # Set the support channel ID (replace with your actual channel ID)
    cog.support_channel_id = 123456789  # Replace with your channel ID
    bot.add_cog(cog) 