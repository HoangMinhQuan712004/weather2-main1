# Environment Setup

Create a `.env` file in the server directory with the following content:

```env
# Weather API Configuration
WEATHER_API_KEY=your_openweather_api_key_here

# Database Configuration
MONGODB_URI=mongodb://localhost:27017/weather-app

# Server Configuration
PORT=5000
NODE_ENV=development

# Discord Bot Configuration (optional)
DISCORD_BOT_TOKEN=your_discord_bot_token_here
DISCORD_CLIENT_ID=your_discord_client_id_here
DISCORD_CLIENT_SECRET=your_discord_client_secret_here
```

## How to get OpenWeather API Key:

1. Go to https://openweathermap.org/api
2. Sign up for a free account
3. Go to API Keys section
4. Copy your API key
5. Replace `your_openweather_api_key_here` with your actual API key

## Important:
- The API key is required for weather data and city search to work
- Without the API key, you'll get "No cities found" errors
- The free tier allows 1000 calls per day
