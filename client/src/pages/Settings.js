import React, { useState, useEffect } from 'react';
import styled from 'styled-components';
import { motion } from 'framer-motion';
import { FiToggleLeft, FiToggleRight, FiSave } from 'react-icons/fi';
import { useTheme } from '../contexts/ThemeContext';

const SettingsContainer = styled.div`
  padding: 100px 20px 40px 20px;
  max-width: 900px;
  margin: 0 auto;
  color: var(--text-color);
  background: linear-gradient(135deg, var(--background-color) 0%, var(--card-background) 100%);
  min-height: 100vh;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', sans-serif;

  h1 {
    font-size: 2.8rem;
    margin-bottom: 10px;
    color: var(--text-color);
    text-align: center;
    font-weight: 700;
  }

  .subtitle {
    text-align: center;
    color: var(--text-color);
    opacity: 0.7;
    margin-bottom: 40px;
    font-size: 1.1rem;
  }

  h2 {
    font-size: 1.6rem;
    margin-top: 50px;
    margin-bottom: 25px;
    color: var(--primary-accent);
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 10px;
    padding-bottom: 15px;
    border-bottom: 2px solid var(--primary-accent);
    opacity: 0.9;
  }
`;

const SettingGroup = styled(motion.div)`
  display: flex;
  flex-direction: column;
  gap: 15px;
  margin-bottom: 30px;
`;

const SettingItem = styled(motion.div)`
  background: var(--card-background);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 20px 25px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  box-shadow: var(--shadow-md);
  transition: all var(--transition-normal);

  &:hover {
    box-shadow: var(--shadow-lg);
    border-color: var(--primary-accent);
  }

  @media (max-width: 768px) {
    flex-direction: column;
    gap: 15px;
    align-items: flex-start;
  }
`;

const SettingLabel = styled.label`
  font-size: 1.1rem;
  font-weight: 500;
  color: var(--text-color);
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 10px;
`;

const SettingDescription = styled.p`
  font-size: 0.9rem;
  color: var(--text-color);
  opacity: 0.7;
  margin: 5px 0 0 0;
`;

const InputField = styled.input`
  width: 100%;
  padding: 12px 16px;
  border: 1px solid var(--border-color);
  border-radius: 8px;
  background: var(--transparent-bg);
  color: var(--text-color);
  font-size: 1rem;
  transition: all var(--transition-fast);
  font-family: inherit;

  &::placeholder {
    color: var(--text-color);
    opacity: 0.5;
  }

  &:focus {
    outline: none;
    border-color: var(--primary-accent);
    background: var(--card-background);
    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
  }
`;

const SelectField = styled.select`
  padding: 12px 16px;
  border: 1px solid var(--border-color);
  border-radius: 8px;
  background: var(--transparent-bg);
  color: var(--text-color);
  font-size: 1rem;
  transition: all var(--transition-fast);
  cursor: pointer;
  font-family: inherit;

  &:focus {
    outline: none;
    border-color: var(--primary-accent);
    background: var(--card-background);
  }

  option {
    background: var(--card-background);
    color: var(--text-color);
  }
`;

const ToggleSwitch = styled.button`
  position: relative;
  display: inline-flex;
  align-items: center;
  width: 60px;
  height: 32px;
  background: ${props => props.checked ? 'var(--success-color)' : 'var(--transparent-bg)'};
  border: 1px solid var(--border-color);
  border-radius: 20px;
  padding: 2px;
  cursor: pointer;
  transition: all var(--transition-fast);
  font-size: 16px;

  &:hover {
    background: ${props => props.checked ? 'var(--success-color)' : 'var(--hover-bg)'};
  }

  svg {
    margin: 0 4px;
    color: ${props => props.checked ? 'white' : 'var(--text-color)'};
  }
`;

const TimeInput = styled.input`
  padding: 12px 16px;
  border: 1px solid var(--border-color);
  border-radius: 8px;
  background: var(--transparent-bg);
  color: var(--text-color);
  font-size: 1rem;
  transition: all var(--transition-fast);
  font-family: inherit;

  &:focus {
    outline: none;
    border-color: var(--primary-accent);
    background: var(--card-background);
  }
`;

const SaveButton = styled.button`
  padding: 14px 28px;
  background: linear-gradient(135deg, var(--primary-accent) 0%, var(--secondary-accent) 100%);
  color: white;
  border: none;
  border-radius: 10px;
  font-size: 1rem;
  font-weight: 600;
  cursor: pointer;
  transition: all var(--transition-fast);
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 20px;
  box-shadow: var(--shadow-md);

  &:hover {
    transform: translateY(-2px);
    box-shadow: var(--shadow-lg);
  }

  &:active {
    transform: translateY(0);
  }
`;

const Settings = () => {
  const { theme, toggleTheme } = useTheme();
  const [discordWebhook, setDiscordWebhook] = useState('');
  const [notificationsEnabled, setNotificationsEnabled] = useState(false);
  const [notificationTime, setNotificationTime] = useState('09:00');
  const [saveMessage, setSaveMessage] = useState('');

  useEffect(() => {
    const storedWebhook = localStorage.getItem('discordWebhook');
    if (storedWebhook) {
      setDiscordWebhook(storedWebhook);
    }

    const storedNotificationsEnabled = localStorage.getItem('notificationsEnabled');
    if (storedNotificationsEnabled !== null) {
      setNotificationsEnabled(JSON.parse(storedNotificationsEnabled));
    }

    const storedNotificationTime = localStorage.getItem('notificationTime');
    if (storedNotificationTime) {
      setNotificationTime(storedNotificationTime);
    }
  }, []);

  const handleWebhookChange = (e) => {
    const { value } = e.target;
    setDiscordWebhook(value);
    localStorage.setItem('discordWebhook', value);
  };

  const handleNotificationsToggle = () => {
    setNotificationsEnabled((prev) => {
      localStorage.setItem('notificationsEnabled', JSON.stringify(!prev));
      return !prev;
    });
  };

  const handleNotificationTimeChange = (e) => {
    const { value } = e.target;
    setNotificationTime(value);
    localStorage.setItem('notificationTime', value);
  };

  const handleSave = () => {
    setSaveMessage('Settings saved successfully!');
    setTimeout(() => setSaveMessage(''), 2000);
  };

  return (
    <SettingsContainer>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <h1>⚙️ Settings</h1>
        <p className="subtitle">Customize your Weather App experience</p>

        <h2>🎨 Appearance</h2>
        <SettingGroup>
          <SettingItem
            whileHover={{ scale: 1.01 }}
            whileTap={{ scale: 0.99 }}
          >
            <div>
              <SettingLabel>
                {theme === 'light' ? '☀️' : '🌙'} Dark Mode
              </SettingLabel>
              <SettingDescription>
                {theme === 'light' ? 'Switch to dark theme for better visibility at night' : 'Switch to light theme'}
              </SettingDescription>
            </div>
            <ToggleSwitch
              checked={theme === 'dark'}
              onClick={toggleTheme}
            >
              {theme === 'dark' ? <FiToggleRight /> : <FiToggleLeft />}
            </ToggleSwitch>
          </SettingItem>
        </SettingGroup>

        <h2>🔔 Notifications</h2>
        <SettingGroup>
          <SettingItem
            whileHover={{ scale: 1.01 }}
            whileTap={{ scale: 0.99 }}
          >
            <div>
              <SettingLabel>Enable Notifications</SettingLabel>
              <SettingDescription>
                Receive daily weather updates
              </SettingDescription>
            </div>
            <ToggleSwitch
              checked={notificationsEnabled}
              onClick={handleNotificationsToggle}
            >
              {notificationsEnabled ? <FiToggleRight /> : <FiToggleLeft />}
            </ToggleSwitch>
          </SettingItem>

          {notificationsEnabled && (
            <SettingItem
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              whileHover={{ scale: 1.01 }}
            >
              <div>
                <SettingLabel>Notification Time</SettingLabel>
                <SettingDescription>
                  Choose when you want to receive notifications
                </SettingDescription>
              </div>
              <TimeInput
                type="time"
                value={notificationTime}
                onChange={handleNotificationTimeChange}
              />
            </SettingItem>
          )}
        </SettingGroup>

        <h2>💬 Integrations</h2>
        <SettingGroup>
          <SettingItem
            whileHover={{ scale: 1.01 }}
            whileTap={{ scale: 0.99 }}
          >
            <div style={{ width: '100%' }}>
              <SettingLabel>Discord Webhook URL</SettingLabel>
              <SettingDescription>
                Get weather updates in your Discord server
              </SettingDescription>
              <InputField
                type="text"
                placeholder="https://discord.com/api/webhooks/..."
                value={discordWebhook}
                onChange={handleWebhookChange}
                style={{ marginTop: '10px' }}
              />
            </div>
          </SettingItem>
        </SettingGroup>

        <SaveButton onClick={handleSave}>
          <FiSave /> Save All Settings
        </SaveButton>

        {saveMessage && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            style={{
              marginTop: '15px',
              padding: '12px 16px',
              background: 'var(--success-color)',
              color: 'white',
              borderRadius: '8px',
              textAlign: 'center',
              fontSize: '0.95rem',
              fontWeight: '500'
            }}
          >
            {saveMessage}
          </motion.div>
        )}
      </motion.div>
    </SettingsContainer>
  );
};

export default Settings;