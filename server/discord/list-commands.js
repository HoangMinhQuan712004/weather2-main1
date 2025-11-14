const { REST, Routes } = require('discord.js');
require('dotenv').config();

const token = process.env.DISCORD_TOKEN;
const clientId = process.env.DISCORD_CLIENT_ID;
const guildId = process.env.GUILD_ID || null; // set GUILD_ID in .env to check guild commands

if (!token || !clientId) {
  console.error('Thiếu DISCORD_TOKEN hoặc DISCORD_CLIENT_ID trong server/.env');
  process.exit(1);
}

(async () => {
  const rest = new REST({ version: '10' }).setToken(token);
  try {
    if (guildId) {
      const cmds = await rest.get(Routes.applicationGuildCommands(clientId, guildId));
      console.log('Guild commands:', JSON.stringify(cmds, null, 2));
    } else {
      const cmds = await rest.get(Routes.applicationCommands(clientId));
      console.log('Global commands:', JSON.stringify(cmds, null, 2));
    }
  } catch (err) {
    console.error('Lỗi khi lấy commands:', err);
  }
})();