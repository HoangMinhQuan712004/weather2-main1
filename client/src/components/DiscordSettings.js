import React, { useState, useEffect } from 'react';
import styled from 'styled-components';
import { motion } from 'framer-motion';
import { FiBell, FiBellOff, FiSettings, FiCheck } from 'react-icons/fi';
import { FaDiscord } from 'react-icons/fa';
import { useWeather } from '../contexts/WeatherContext';
import api from '../services/api';
import toast from 'react-hot-toast';

const DiscordContainer = styled.div`
  background: rgba(255, 255, 255, 0.1);
  backdrop-filter: blur(10px);
  border: 1px solid rgba(255, 255, 255, 0.2);
  border-radius: 20px;
  padding: 30px;
  margin-bottom: 30px;
`;

const Header = styled.div`
  display: flex;
  align-items: center;
  gap: 15px;
  margin-bottom: 25px;
  
  h3 {
    color: white;
    font-size: 1.5rem;
    font-weight: 600;
  }
`;

const StatusCard = styled.div`
  background: rgba(255, 255, 255, 0.1);
  border-radius: 15px;
  padding: 20px;
  margin-bottom: 20px;
  border: 1px solid ${props => props.connected ? 'rgba(34, 197, 94, 0.3)' : 'rgba(239, 68, 68, 0.3)'};
`;

const StatusIndicator = styled.div`
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 15px;
  
  .status-dot {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background: ${props => props.connected ? '#22c55e' : '#ef4444'};
  }
  
  .status-text {
    color: white;
    font-weight: 600;
  }
`;

const StatusInfo = styled.div`
  color: rgba(255, 255, 255, 0.8);
  font-size: 0.9rem;
  line-height: 1.5;
`;

const Button = styled.button`
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 20px;
  background: ${props => props.variant === 'primary' 
    ? 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' 
    : 'rgba(255, 255, 255, 0.1)'};
  border: 1px solid rgba(255, 255, 255, 0.3);
  border-radius: 10px;
  color: white;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.3s ease;
  margin-right: 10px;
  margin-bottom: 10px;

  &:hover {
    transform: translateY(-2px);
    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
  }

  &:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    transform: none;
  }
`;

const Input = styled.input`
  width: 100%;
  padding: 12px 15px;
  border: 1px solid rgba(255, 255, 255, 0.3);
  border-radius: 10px;
  background: rgba(255, 255, 255, 0.1);
  color: white;
  font-size: 14px;
  margin-bottom: 15px;
  transition: all 0.3s ease;

  &::placeholder {
    color: rgba(255, 255, 255, 0.7);
  }

  &:focus {
    outline: none;
    border-color: rgba(255, 255, 255, 0.5);
    background: rgba(255, 255, 255, 0.15);
  }
`;

const Label = styled.label`
  color: white;
  font-size: 14px;
  font-weight: 500;
  margin-bottom: 8px;
  display: block;
`;

const NotificationSettings = styled.div`
  background: rgba(255, 255, 255, 0.05);
  border-radius: 15px;
  padding: 20px;
  margin-top: 20px;
`;

const SettingRow = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 15px;
  
  &:last-child {
    margin-bottom: 0;
  }
`;

const SettingLabel = styled.div`
  color: white;
  font-size: 14px;
  font-weight: 500;
`;

const ToggleButton = styled.button`
  width: 50px;
  height: 25px;
  border-radius: 25px;
  background: ${props => props.active ? '#22c55e' : 'rgba(255, 255, 255, 0.2)'};
  border: none;
  cursor: pointer;
  position: relative;
  transition: all 0.3s ease;

  &::after {
    content: '';
    position: absolute;
    top: 2px;
    left: ${props => props.active ? '27px' : '2px'};
    width: 21px;
    height: 21px;
    border-radius: 50%;
    background: white;
    transition: all 0.3s ease;
  }
`;

const DiscordSettings = () => {
  const [discordStatus, setDiscordStatus] = useState({
    connected: false,
    subscribed: false,
    notificationCity: null,
    lastNotification: null
  });
  const [loading, setLoading] = useState(false);
  const [discordUserId, setDiscordUserId] = useState('');
  const [channelId, setChannelId] = useState('');
  const [notificationCity, setNotificationCity] = useState('');
  const { searchCities } = useWeather();

  useEffect(() => {
    loadDiscordStatus();
  }, []);

  const loadDiscordStatus = async () => {
    try {
      const response = await api.get('/discord/status');
      setDiscordStatus(response.data.discord);
      setNotificationCity(response.data.discord.notificationCity || '');
    } catch (error) {
      console.error('Failed to load Discord status:', error);
    }
  };

  const handleConnectDiscord = async () => {
    if (!discordUserId || !channelId) {
      toast.error('Please enter Discord User ID and Channel ID');
      return;
    }

    try {
      setLoading(true);
      await api.post('/discord/connect', {
        discordUserId,
        channelId
      });
      
      toast.success('Discord account connected successfully!');
      await loadDiscordStatus();
    } catch (error) {
      const message = error.response?.data?.message || 'Failed to connect Discord account';
      toast.error(message);
    } finally {
      setLoading(false);
    }
  };

  const handleSubscribe = async () => {
    if (!notificationCity) {
      toast.error('Please enter a city name');
      return;
    }

    try {
      setLoading(true);
      await api.post('/discord/subscribe', {
        city: notificationCity,
        lat: 0, // This would be fetched from weather API
        lon: 0  // This would be fetched from weather API
      });
      
      toast.success('Subscribed to Discord notifications!');
      await loadDiscordStatus();
    } catch (error) {
      const message = error.response?.data?.message || 'Failed to subscribe to notifications';
      toast.error(message);
    } finally {
      setLoading(false);
    }
  };

  const handleUnsubscribe = async () => {
    try {
  setLoading(true);
  await api.post('/discord/unsubscribe');
      
      toast.success('Unsubscribed from Discord notifications');
      await loadDiscordStatus();
    } catch (error) {
      const message = error.response?.data?.message || 'Failed to unsubscribe from notifications';
      toast.error(message);
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateCity = async () => {
    if (!notificationCity) {
      toast.error('Please enter a city name');
      return;
    }

    try {
      setLoading(true);
      await api.put('/discord/update-city', {
        city: notificationCity
      });
      
      toast.success('Notification city updated!');
      await loadDiscordStatus();
    } catch (error) {
      const message = error.response?.data?.message || 'Failed to update notification city';
      toast.error(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <DiscordContainer>
      <Header>
        <FaDiscord style={{ fontSize: '1.5rem', color: '#5865F2' }} />
        <h3>Discord Notifications</h3>
      </Header>

      <StatusCard connected={discordStatus.connected}>
        <StatusIndicator connected={discordStatus.connected}>
          <div className="status-dot" />
          <span className="status-text">
            {discordStatus.connected ? 'Connected' : 'Not Connected'}
          </span>
        </StatusIndicator>
        <StatusInfo>
          {discordStatus.connected ? (
            <>
              <p>✅ Discord account is connected</p>
              <p>📱 Notifications: {discordStatus.subscribed ? 'Enabled' : 'Disabled'}</p>
              {discordStatus.notificationCity && (
                <p>🌍 City: {discordStatus.notificationCity}</p>
              )}
              {discordStatus.lastNotification && (
                <p>⏰ Last notification: {new Date(discordStatus.lastNotification).toLocaleString()}</p>
              )}
            </>
          ) : (
            <p>Connect your Discord account to receive weather notifications</p>
          )}
        </StatusInfo>
      </StatusCard>

      {!discordStatus.connected ? (
        <div>
          <Label>Discord User ID</Label>
          <Input
            type="text"
            placeholder="Your Discord User ID"
            value={discordUserId}
            onChange={(e) => setDiscordUserId(e.target.value)}
          />
          
          <Label>Channel ID (optional)</Label>
          <Input
            type="text"
            placeholder="Discord Channel ID (leave empty for DMs)"
            value={channelId}
            onChange={(e) => setChannelId(e.target.value)}
          />
          
          <Button 
            variant="primary" 
            onClick={handleConnectDiscord}
            disabled={loading}
          >
            <FaDiscord />
            Connect Discord Account
          </Button>
        </div>
      ) : (
        <NotificationSettings>
          <h4 style={{ color: 'white', marginBottom: '20px', fontSize: '1.1rem' }}>
            Notification Settings
          </h4>
          
          <SettingRow>
            <SettingLabel>Hourly Weather Updates</SettingLabel>
            <ToggleButton
              active={discordStatus.subscribed}
              onClick={discordStatus.subscribed ? handleUnsubscribe : handleSubscribe}
            />
          </SettingRow>

          {discordStatus.subscribed && (
            <div>
              <Label>Notification City</Label>
              <Input
                type="text"
                placeholder="Enter city name for notifications"
                value={notificationCity}
                onChange={(e) => setNotificationCity(e.target.value)}
              />
              
              <Button 
                variant="primary" 
                onClick={handleUpdateCity}
                disabled={loading}
              >
                <FiCheck />
                Update City
              </Button>
            </div>
          )}

          <div style={{ marginTop: '20px' }}>
            <Button 
              variant="primary" 
              onClick={discordStatus.subscribed ? handleUnsubscribe : handleSubscribe}
              disabled={loading}
            >
              {discordStatus.subscribed ? (
                <>
                  <FiBellOff />
                  Unsubscribe
                </>
              ) : (
                <>
                  <FiBell />
                  Subscribe to Notifications
                </>
              )}
            </Button>
          </div>
        </NotificationSettings>
      )}

      <div style={{ marginTop: '20px', padding: '15px', background: 'rgba(255, 255, 255, 0.05)', borderRadius: '10px' }}>
        <h4 style={{ color: 'white', marginBottom: '10px', fontSize: '1rem' }}>
          📋 How to use Discord Bot:
        </h4>
        <ul style={{ color: 'rgba(255, 255, 255, 0.8)', fontSize: '0.9rem', lineHeight: '1.6' }}>
          <li>Use <code>/weather [city]</code> to get current weather</li>
          <li>Use <code>/forecast [city]</code> to get 5-day forecast</li>
          <li>Use <code>/subscribe [city] [userid]</code> to subscribe to hourly updates</li>
          <li>Use <code>/unsubscribe</code> to stop notifications</li>
        </ul>
      </div>
    </DiscordContainer>
  );
};

export default DiscordSettings;
