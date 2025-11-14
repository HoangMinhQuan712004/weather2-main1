const { Client, GatewayIntentBits } = require('discord.js');
require('dotenv').config();

// Simple test to verify Discord bot connection
const client = new Client({
  intents: [GatewayIntentBits.Guilds]
});

client.once('ready', () => {
  console.log(`✅ Discord bot logged in as ${client.user.tag}!`);
  console.log(`Bot ID: ${client.user.id}`);
  console.log(`Bot is in ${client.guilds.cache.size} server(s)`);
  process.exit(0);
});

client.on('error', (error) => {
  console.error('❌ Discord bot error:', error);
  process.exit(1);
});

// Test connection
console.log('🔄 Testing Discord bot connection...');
client.login(process.env.DISCORD_TOKEN).catch((error) => {
  console.error('❌ Failed to login:', error.message);
  console.log('\n📋 Troubleshooting:');
  console.log('1. Check if DISCORD_TOKEN is set in your .env file');
  console.log('2. Verify the token is correct');
  console.log('3. Make sure the bot is invited to a server');
  process.exit(1);
});
