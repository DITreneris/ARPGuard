import discord
from discord.ext import commands
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import asyncio
import matplotlib.pyplot as plt
import io

class AnalyticsCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.analytics_file = 'src/community/data/analytics.json'
        self.analytics = self._load_analytics()
        self.demo_tier_users = set()
        self.conversion_events = []

    def _load_analytics(self) -> Dict:
        """Load analytics data from JSON file."""
        try:
            with open(self.analytics_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {
                "demo_users": {},
                "conversions": [],
                "feature_usage": {},
                "daily_stats": {},
                "retention": {}
            }

    def _save_analytics(self):
        """Save analytics data to JSON file."""
        os.makedirs(os.path.dirname(self.analytics_file), exist_ok=True)
        with open(self.analytics_file, 'w') as f:
            json.dump(self.analytics, f, indent=4)

    def _update_daily_stats(self):
        """Update daily statistics."""
        today = datetime.utcnow().strftime('%Y-%m-%d')
        if today not in self.analytics["daily_stats"]:
            self.analytics["daily_stats"][today] = {
                "new_demo_users": 0,
                "conversions": 0,
                "active_users": 0,
                "feature_usage": {}
            }

    @commands.command(name='trackdemo')
    async def track_demo_user(self, ctx, user: discord.Member):
        """Track a new Demo Tier user (Admin only)."""
        if not ctx.author.guild_permissions.administrator:
            await ctx.send("You don't have permission to use this command.")
            return

        user_id = str(user.id)
        if user_id in self.analytics["demo_users"]:
            await ctx.send(f"{user.mention} is already being tracked as a Demo Tier user.")
            return

        self.analytics["demo_users"][user_id] = {
            "joined_at": datetime.utcnow().isoformat(),
            "last_active": datetime.utcnow().isoformat(),
            "features_used": [],
            "converted": False
        }

        self._update_daily_stats()
        self.analytics["daily_stats"][datetime.utcnow().strftime('%Y-%m-%d')]["new_demo_users"] += 1
        self.demo_tier_users.add(user_id)
        self._save_analytics()

        await ctx.send(f"Now tracking {user.mention} as a Demo Tier user.")

    @commands.command(name='trackconversion')
    async def track_conversion(self, ctx, user: discord.Member):
        """Track a Demo Tier to Premium conversion (Admin only)."""
        if not ctx.author.guild_permissions.administrator:
            await ctx.send("You don't have permission to use this command.")
            return

        user_id = str(user.id)
        if user_id not in self.analytics["demo_users"]:
            await ctx.send(f"{user.mention} is not a tracked Demo Tier user.")
            return

        if self.analytics["demo_users"][user_id]["converted"]:
            await ctx.send(f"{user.mention} has already been marked as converted.")
            return

        self.analytics["demo_users"][user_id]["converted"] = True
        self.analytics["demo_users"][user_id]["converted_at"] = datetime.utcnow().isoformat()

        conversion_data = {
            "user_id": user_id,
            "converted_at": datetime.utcnow().isoformat(),
            "time_to_convert": (
                datetime.fromisoformat(self.analytics["demo_users"][user_id]["converted_at"]) -
                datetime.fromisoformat(self.analytics["demo_users"][user_id]["joined_at"])
            ).total_seconds() / 86400  # Convert to days
        }

        self.analytics["conversions"].append(conversion_data)
        self._update_daily_stats()
        self.analytics["daily_stats"][datetime.utcnow().strftime('%Y-%m-%d')]["conversions"] += 1
        self._save_analytics()

        await ctx.send(f"Tracked conversion for {user.mention} to Premium Tier.")

    @commands.command(name='trackfeature')
    async def track_feature_usage(self, ctx, feature: str):
        """Track feature usage by Demo Tier users."""
        user_id = str(ctx.author.id)
        if user_id not in self.analytics["demo_users"]:
            await ctx.send("This command is only for Demo Tier users.")
            return

        if feature not in self.analytics["feature_usage"]:
            self.analytics["feature_usage"][feature] = {
                "total_uses": 0,
                "demo_users": set()
            }

        self.analytics["feature_usage"][feature]["total_uses"] += 1
        self.analytics["feature_usage"][feature]["demo_users"].add(user_id)
        self.analytics["demo_users"][user_id]["features_used"].append({
            "feature": feature,
            "used_at": datetime.utcnow().isoformat()
        })
        self.analytics["demo_users"][user_id]["last_active"] = datetime.utcnow().isoformat()

        self._update_daily_stats()
        today = datetime.utcnow().strftime('%Y-%m-%d')
        if feature not in self.analytics["daily_stats"][today]["feature_usage"]:
            self.analytics["daily_stats"][today]["feature_usage"][feature] = 0
        self.analytics["daily_stats"][today]["feature_usage"][feature] += 1

        self._save_analytics()
        await ctx.send(f"Tracked usage of feature: {feature}")

    @commands.command(name='analytics')
    async def show_analytics(self, ctx, timeframe: str = "7d"):
        """Show analytics dashboard (Admin only)."""
        if not ctx.author.guild_permissions.administrator:
            await ctx.send("You don't have permission to use this command.")
            return

        # Parse timeframe
        days = int(timeframe[:-1])
        if timeframe[-1] != 'd':
            await ctx.send("Invalid timeframe format. Use '7d', '30d', etc.")
            return

        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        # Prepare data
        daily_stats = {
            date: stats for date, stats in self.analytics["daily_stats"].items()
            if start_date <= datetime.strptime(date, '%Y-%m-%d') <= end_date
        }

        # Create plots
        plt.figure(figsize=(12, 8))

        # Plot 1: New Demo Users and Conversions
        plt.subplot(2, 1, 1)
        dates = sorted(daily_stats.keys())
        new_users = [daily_stats[date]["new_demo_users"] for date in dates]
        conversions = [daily_stats[date]["conversions"] for date in dates]

        plt.plot(dates, new_users, label='New Demo Users', marker='o')
        plt.plot(dates, conversions, label='Conversions', marker='o')
        plt.title('Demo Users and Conversions Over Time')
        plt.xticks(rotation=45)
        plt.legend()

        # Plot 2: Feature Usage
        plt.subplot(2, 1, 2)
        feature_usage = {}
        for date, stats in daily_stats.items():
            for feature, count in stats["feature_usage"].items():
                if feature not in feature_usage:
                    feature_usage[feature] = 0
                feature_usage[feature] += count

        features = list(feature_usage.keys())
        usage = list(feature_usage.values())

        plt.bar(features, usage)
        plt.title('Feature Usage')
        plt.xticks(rotation=45)

        # Save plot to buffer
        buffer = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        plt.close()

        # Create embed with statistics
        embed = discord.Embed(
            title=f"Analytics Dashboard ({timeframe})",
            color=discord.Color.blue()
        )

        total_demo_users = len(self.analytics["demo_users"])
        total_conversions = len([u for u in self.analytics["demo_users"].values() if u["converted"]])
        conversion_rate = (total_conversions / total_demo_users * 100) if total_demo_users > 0 else 0

        embed.add_field(
            name="Overall Statistics",
            value=f"Total Demo Users: {total_demo_users}\n"
                  f"Total Conversions: {total_conversions}\n"
                  f"Conversion Rate: {conversion_rate:.2f}%",
            inline=False
        )

        # Send embed and plot
        await ctx.send(embed=embed)
        await ctx.send(file=discord.File(buffer, 'analytics.png'))

    @commands.Cog.listener()
    async def on_message(self, message):
        """Track user activity."""
        if message.author.bot:
            return

        user_id = str(message.author.id)
        if user_id in self.analytics["demo_users"]:
            self.analytics["demo_users"][user_id]["last_active"] = datetime.utcnow().isoformat()
            self._save_analytics()

def setup(bot):
    bot.add_cog(AnalyticsCog(bot)) 