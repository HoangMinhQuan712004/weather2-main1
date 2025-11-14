const { Client, GatewayIntentBits, EmbedBuilder, SlashCommandBuilder, REST, Routes } = require('discord.js');
const cron = require('node-cron');
const axios = require('axios');
const mongoose = require('mongoose');
require('dotenv').config();

// Import User model
const User = require('../models/User');

class WeatherDiscordBot {
  constructor() {
    this.client = new Client({
      intents: [
        GatewayIntentBits.Guilds
      ]
    });

    this.setupEventHandlers();
    this.setupCommands();
    this.setupScheduledNotifications();
  }

  setupEventHandlers() {
    this.client.once('ready', () => {
      console.log(`Discord bot logged in as ${this.client.user.tag}!`);
      this.registerSlashCommands();
    });

    this.client.on('interactionCreate', async (interaction) => {
      if (!interaction.isChatInputCommand()) return;

      const { commandName } = interaction;

      try {
        switch (commandName) {
          case 'weather':
            await this.handleWeatherCommand(interaction);
            break;
          case 'subscribe':
            await this.handleSubscribeCommand(interaction);
            break;
          case 'unsubscribe':
            await this.handleUnsubscribeCommand(interaction);
            break;
          case 'forecast':
            await this.handleForecastCommand(interaction);
            break;
          default:
            await interaction.reply({ content: 'Unknown command!', ephemeral: true });
        }
      } catch (error) {
        console.error('Error handling command:', error);
        await interaction.reply({ 
          content: 'An error occurred while processing your command.', 
          ephemeral: true 
        });
      }
    });
  }

  setupCommands() {
    this.commands = [
      new SlashCommandBuilder()
        .setName('weather')
        .setDescription('Get current weather for a city')
        .addStringOption(option =>
          option.setName('city')
            .setDescription('City name')
            .setRequired(true)
        ),

      new SlashCommandBuilder()
        .setName('subscribe')
        .setDescription('Subscribe to hourly weather notifications')
        .addStringOption(option =>
          option.setName('city')
            .setDescription('City name for notifications')
            .setRequired(true)
        )
        .addStringOption(option =>
          option.setName('email')
            .setDescription('The email you used to register for the weather app')
            .setRequired(true)
        ),

      new SlashCommandBuilder()
        .setName('unsubscribe')
        .setDescription('Unsubscribe from weather notifications'),

      new SlashCommandBuilder()
        .setName('forecast')
        .setDescription('Get 5-day weather forecast')
        .addStringOption(option =>
          option.setName('city')
            .setDescription('City name')
            .setRequired(true)
        )
    ];
  }

  async registerSlashCommands() {
    const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_TOKEN);

    try {
      console.log('Started refreshing application (/) commands.');

      await rest.put(
        Routes.applicationCommands(process.env.DISCORD_CLIENT_ID),
        { body: this.commands }
      );

      console.log('Successfully reloaded application (/) commands.');
    } catch (error) {
      console.error('Error registering commands:', error);
    }
  }

  async handleWeatherCommand(interaction) {
    const city = interaction.options.getString('city');
    
    try {
      const weatherData = await this.getWeatherData(city);
      const embed = this.createWeatherEmbed(weatherData);
      
      await interaction.reply({ embeds: [embed] });
    } catch (error) {
      await interaction.reply({ 
        content: `Could not find weather data for ${city}. Please check the city name.`, 
        ephemeral: true 
      });
    }
  }

  async handleSubscribeCommand(interaction) {
    const city = interaction.options.getString('city');
    const email = interaction.options.getString('email');
    const discordUserId = interaction.user.id;

    try {
      // Find user by email and update Discord info
      const user = await User.findOne({ email });
      if (!user) {
        await interaction.reply({ 
          content: 'User not found. Please make sure you have an account in the weather app with that email.', 
          ephemeral: true 
        });
        return;
      }

      // Get weather data to verify city exists
      const weatherData = await this.getWeatherData(city);
      
      // Update user with Discord info and notification preferences
      user.discord = {
        userId: discordUserId,
        channelId: interaction.channelId,
        subscribed: true,
        notificationCity: city,
        lastNotification: null
      };

      await user.save();

      const embed = new EmbedBuilder()
        .setTitle('🌤️ Weather Notifications Subscribed!')
        .setDescription(`You will now receive hourly weather updates for **${city}**`)
        .addFields(
          { name: 'Current Weather', value: `${weatherData.temperature}°C - ${weatherData.description}`, inline: true },
          { name: 'Humidity', value: `${weatherData.humidity}%`, inline: true },
          { name: 'Wind Speed', value: `${weatherData.windSpeed} km/h`, inline: true }
        )
        .setColor(0x00AE86)
        .setTimestamp();

      await interaction.reply({ embeds: [embed] });
    } catch (error) {
      console.error('Subscribe error:', error);
      await interaction.reply({ 
        content: `Error subscribing to notifications. Please check the city name and try again.`, 
        ephemeral: true 
      });
    }
  }

  async handleUnsubscribeCommand(interaction) {
    const discordUserId = interaction.user.id;

    try {
      const user = await User.findOne({ 'discord.userId': discordUserId });
      if (!user || !user.discord?.subscribed) {
        await interaction.reply({ 
          content: 'You are not subscribed to weather notifications.', 
          ephemeral: true 
        });
        return;
      }

      user.discord.subscribed = false;
      user.discord.notificationCity = null;
      await user.save();

      await interaction.reply({ 
        content: '✅ Successfully unsubscribed from weather notifications.', 
        ephemeral: true 
      });
    } catch (error) {
      console.error('Unsubscribe error:', error);
      await interaction.reply({ 
        content: 'Error unsubscribing from notifications.', 
        ephemeral: true 
      });
    }
  }

  async handleForecastCommand(interaction) {
    const city = interaction.options.getString('city');
    
    try {
      const forecastData = await this.getForecastData(city);
      const embed = this.createForecastEmbed(forecastData);
      
      await interaction.reply({ embeds: [embed] });
    } catch (error) {
      await interaction.reply({ 
        content: `Could not find forecast data for ${city}. Please check the city name.`, 
        ephemeral: true 
      });
    }
  }

  async getWeatherData(city) {
    const response = await axios.get('https://api.openweathermap.org/data/2.5/weather', {
      params: {
        q: city,
        appid: process.env.WEATHER_API_KEY,
        units: 'metric'
      }
    });

    const data = response.data;
    return {
      city: data.name,
      country: data.sys.country,
      temperature: Math.round(data.main.temp),
      feelsLike: Math.round(data.main.feels_like),
      humidity: data.main.humidity,
      windSpeed: data.wind.speed,
      description: data.weather[0].description,
      icon: data.weather[0].icon,
      main: data.weather[0].main
    };
  }

  async getForecastData(city) {
    const response = await axios.get('https://api.openweathermap.org/data/2.5/forecast', {
      params: {
        q: city,
        appid: process.env.WEATHER_API_KEY,
        units: 'metric'
      }
    });

    return response.data;
  }

  createWeatherEmbed(weatherData) {
    const weatherEmojis = {
      'Clear': '☀️',
      'Clouds': '☁️',
      'Rain': '🌧️',
      'Snow': '❄️',
      'Thunderstorm': '⛈️',
      'Mist': '🌫️',
      'Fog': '🌫️'
    };

    const emoji = weatherEmojis[weatherData.main] || '🌤️';

    return new EmbedBuilder()
      .setTitle(`${emoji} Weather in ${weatherData.city}, ${weatherData.country}`)
      .setDescription(`**${weatherData.temperature}°C** - ${weatherData.description}`)
      .addFields(
        { name: '🌡️ Feels Like', value: `${weatherData.feelsLike}°C`, inline: true },
        { name: '💧 Humidity', value: `${weatherData.humidity}%`, inline: true },
        { name: '💨 Wind Speed', value: `${weatherData.windSpeed} km/h`, inline: true }
      )
      .setColor(this.getWeatherColor(weatherData.main))
      .setTimestamp()
      .setFooter({ text: 'Weather Bot • Powered by OpenWeatherMap' });
  }

  createForecastEmbed(forecastData) {
    const embed = new EmbedBuilder()
      .setTitle(`🌤️ 5-Day Forecast for ${forecastData.city.name}, ${forecastData.city.country}`)
      .setColor(0x00AE86)
      .setTimestamp()
      .setFooter({ text: 'Weather Bot • Powered by OpenWeatherMap' });

    // Group forecast by day
    const dailyForecast = {};
    forecastData.list.forEach(item => {
      const date = new Date(item.dt * 1000);
      const dateKey = date.toDateString();
      
      if (!dailyForecast[dateKey]) {
        dailyForecast[dateKey] = {
          date: date,
          temps: [],
          weather: item.weather[0]
        };
      }
      
      dailyForecast[dateKey].temps.push(item.main.temp);
    });

    // Add daily forecast to embed
    Object.values(dailyForecast).slice(0, 5).forEach(day => {
      const minTemp = Math.round(Math.min(...day.temps));
      const maxTemp = Math.round(Math.max(...day.temps));
      const dateStr = day.date.toLocaleDateString('en-US', { 
        weekday: 'short', 
        month: 'short', 
        day: 'numeric' 
      });

      embed.addFields({
        name: dateStr,
        value: `${minTemp}°C - ${maxTemp}°C • ${day.weather.description}`,
        inline: false
      });
    });

    return embed;
  }

  getWeatherColor(weatherMain) {
    const colors = {
      'Clear': 0xFFD700,
      'Clouds': 0x87CEEB,
      'Rain': 0x4682B4,
      'Snow': 0xE6E6FA,
      'Thunderstorm': 0x2F4F4F,
      'Mist': 0xC0C0C0,
      'Fog': 0xC0C0C0
    };
    return colors[weatherMain] || 0x00AE86;
  }

  setupScheduledNotifications() {
    // Send hourly weather notifications at the top of every hour
    cron.schedule('0 * * * *', async () => {
      console.log('Running hourly weather notifications...');
      await this.sendHourlyNotifications();
    });

    // Send daily weather summary at 8 AM
    cron.schedule('0 8 * * *', async () => {
      console.log('Running daily weather summary...');
      await this.sendDailySummary();
    });
  }

  async sendHourlyNotifications() {
    try {
      const subscribedUsers = await User.find({ 
        'discord.subscribed': true,
        'discord.userId': { $exists: true }
      });

      for (const user of subscribedUsers) {
        try {
          const weatherData = await this.getWeatherData(user.discord.notificationCity);
          const embed = this.createWeatherEmbed(weatherData);
          
          // Send notification to user's DM or channel
          const channel = await this.client.channels.fetch(user.discord.channelId);
          await channel.send({ 
            content: `🌤️ **Hourly Weather Update for ${user.discord.notificationCity}**`,
            embeds: [embed] 
          });

          // Update last notification time
          user.discord.lastNotification = new Date();
          await user.save();

          console.log(`Sent hourly notification to user ${user.username} for ${user.discord.notificationCity}`);
        } catch (error) {
          console.error(`Error sending notification to user ${user.username}:`, error);
        }
      }
    } catch (error) {
      console.error('Error in hourly notifications:', error);
    }
  }

  async sendDailySummary() {
    try {
      const subscribedUsers = await User.find({ 
        'discord.subscribed': true,
        'discord.userId': { $exists: true }
      });

      for (const user of subscribedUsers) {
        try {
          const forecastData = await this.getForecastData(user.discord.notificationCity);
          const embed = this.createForecastEmbed(forecastData);
          
          const channel = await this.client.channels.fetch(user.discord.channelId);
          await channel.send({ 
            content: `🌅 **Daily Weather Summary for ${user.discord.notificationCity}**`,
            embeds: [embed] 
          });

          console.log(`Sent daily summary to user ${user.username} for ${user.discord.notificationCity}`);
        } catch (error) {
          console.error(`Error sending daily summary to user ${user.username}:`, error);
        }
      }
    } catch (error) {
      console.error('Error in daily summary:', error);
    }
  }

  async start() {
    try {
      // Connect to MongoDB
      await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/weather-app');
      console.log('Connected to MongoDB');

      // Login to Discord
      await this.client.login(process.env.DISCORD_TOKEN);
    } catch (error) {
      console.error('Error starting Discord bot:', error);
      process.exit(1);
    }
  }
}

// Start the bot
const bot = new WeatherDiscordBot();
bot.start();

module.exports = WeatherDiscordBot;
