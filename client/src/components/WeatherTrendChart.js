import React, { useState, useEffect } from 'react';
import { Line } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend } from 'chart.js';
import { getHistoricalWeather } from '../services/api';
import styled from 'styled-components';
import LoadingSpinner from './LoadingSpinner';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend
);

const ChartContainer = styled.div`
  background: var(--card-background-light);
  border: 1px solid var(--border-color-light);
  border-radius: 15px;
  padding: 20px;
  margin-top: 20px;
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
  color: var(--text-color-light);

  h3 {
    text-align: center;
    margin-bottom: 20px;
    color: var(--text-color-light);
  }
`;

const WeatherTrendChart = ({ lat, lon }) => {
  const [chartData, setChartData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchHistoricalData = async () => {
      if (!lat || !lon) return;

      setLoading(true);
      setError(null);
      setChartData(null);

      try {
        const historicalTemps = [];
        const labels = [];
        const today = new Date();

        // Fetch data for the past 7 days (excluding today)
        for (let i = 6; i >= 0; i--) {
          const date = new Date(today);
          date.setDate(today.getDate() - i);
          date.setHours(12, 0, 0, 0); // Get data for noon each day
          const timestamp = Math.floor(date.getTime() / 1000);

          const response = await getHistoricalWeather(lat, lon, timestamp);
          
          if (response && response.data && response.data.length > 0) {
            // OpenWeatherMap One Call API returns an array of hourly data for the day
            // We'll take the temperature closest to noon (index 12 for 24-hour data)
            const noonData = response.data.find(item => new Date(item.dt * 1000).getHours() === 12);
            if (noonData) {
              historicalTemps.push(noonData.temp);
              labels.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
            }
          } else if (response && response.current && response.current.temp) {
            // Fallback for older historical API or different response structure
            historicalTemps.push(response.current.temp);
            labels.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
          }
        }

        if (historicalTemps.length > 0) {
          setChartData({
            labels,
            datasets: [
              {
                label: 'Temperature (°C)',
                data: historicalTemps,
                fill: false,
                borderColor: 'rgb(75, 192, 192)',
                tension: 0.1,
              },
            ],
          });
        }
      } catch (err) {
        console.error('Failed to fetch historical weather data:', err);
        setError('Failed to load historical data. Please try again later.');
      } finally {
        setLoading(false);
      }
    };

    fetchHistoricalData();
  }, [lat, lon]);

  if (loading) {
    return <LoadingSpinner />;
  }

  if (error) {
    return <ChartContainer><p style={{ color: 'red' }}>{error}</p></ChartContainer>;
  }

  if (!chartData) {
    return <ChartContainer><p>No historical data available for this location.</p></ChartContainer>;
  }

  const options = {
    responsive: true,
    plugins: {
      legend: {
        position: 'top',
        labels: {
          color: 'var(--text-color-light)', // Theme-aware legend text
        },
      },
      title: {
        display: true,
        text: '7-Day Temperature Trend',
        color: 'var(--text-color-light)', // Theme-aware title text
      },
    },
    scales: {
      x: {
        ticks: {
          color: 'var(--text-color-light)', // Theme-aware x-axis ticks
        },
        grid: {
          color: 'rgba(255, 255, 255, 0.1)', // Theme-aware grid lines
        },
      },
      y: {
        ticks: {
          color: 'var(--text-color-light)', // Theme-aware y-axis ticks
        },
        grid: {
          color: 'rgba(255, 255, 255, 0.1)', // Theme-aware grid lines
        },
      },
    },
  };

  return (
    <ChartContainer>
      <h3>7-Day Temperature Trend</h3>
      <Line data={chartData} options={options} />
    </ChartContainer>
  );
};

export default WeatherTrendChart;
