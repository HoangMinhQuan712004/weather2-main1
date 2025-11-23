require('dotenv').config();
const axios = require('axios');

const KEY = process.env.WEATHER_API_KEY;
if (!KEY) {
  console.error('No WEATHER_API_KEY found in environment. Please set it in server/.env');
  process.exit(1);
}

const test = async () => {
  try {
    // Basic current weather test for Hanoi (lat/lon from logs)
    const lat = 21.0239;
    const lon = 105.8079;
    const url = `https://api.openweathermap.org/data/2.5/weather?lat=${lat}&lon=${lon}&appid=${KEY}`;
    console.log('Testing OpenWeather current weather endpoint...');
    const resp = await axios.get(url, { timeout: 10000 });
    console.log('Status:', resp.status);
    console.log('Sample data keys:', Object.keys(resp.data).slice(0, 10));
    console.log('Success — API key appears valid for current weather endpoint.');
  } catch (err) {
    if (err.response && err.response.data) {
      console.error('OpenWeather responded with:', JSON.stringify(err.response.data, null, 2));
    } else {
      console.error('Request error:', err.message);
    }
    process.exit(2);
  }
};

test();
