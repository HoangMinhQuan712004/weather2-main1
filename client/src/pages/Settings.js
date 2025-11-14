import React, { useState, useEffect } from 'react';
import styled from 'styled-components';
import { useTheme } from '../contexts/ThemeContext';

const SettingsContainer = styled.div`
  padding: 80px 20px 20px 20px; /* Adjust padding to account for fixed header */
  max-width: 800px;
  margin: 0 auto;
  color: var(--text-color-light);

  h1 {
    font-size: 2.5rem;
    margin-bottom: 30px;
    color: var(--text-color-light);
    text-align: center;
  }

  h2 {
    font-size: 1.8rem;
    margin-top: 40px;
    margin-bottom: 20px;
    color: var(--text-color-light);
  }

  .setting-item {
    background: var(--card-background-light);
    border: 1px solid var(--border-color-light);
    border-radius: 15px;
    padding: 20px;
    margin-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
  }

  .setting-item label {
    font-size: 1.2rem;
    font-weight: 500;
  }

  .input-field {
    width: 100%;
    padding: 10px;
    border: 1px solid var(--border-color-light);
    border-radius: 8px;
    background: var(--header-background-light);
    color: var(--text-color-light);
    font-size: 1rem;
    margin-top: 10px;
  }

  .input-field::placeholder {
    color: var(--text-color-light);
    opacity: 0.7;
  }

  .theme-switch {
    position: relative;
    display: inline-block;
    width: 60px;
    height: 34px;
  }

  .theme-switch input {
    opacity: 0;
    width: 0;
    height: 0;
  }

  .slider {
    position: absolute;
    cursor: pointer;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background-color: #ccc;
    -webkit-transition: .4s;
    transition: .4s;
    border-radius: 34px;
  }

  .slider:before {
    position: absolute;
    content: "";
    height: 26px;
    width: 26px;
    left: 4px;
    bottom: 4px;
    background-color: white;
    -webkit-transition: .4s;
    transition: .4s;
    border-radius: 50%;
  }

  input:checked + .slider {
    background-color: #2196F3;
  }

  input:focus + .slider {
    box-shadow: 0 0 1px #2196F3;
  }

  input:checked + .slider:before {
    -webkit-transform: translateX(26px);
    -ms-transform: translateX(26px);
    transform: translateX(26px);
  }

  .time-picker {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .time-picker input[type="time"] {
    padding: 8px;
    border: 1px solid var(--border-color-light);
    border-radius: 8px;
    background: var(--header-background-light);
    color: var(--text-color-light);
    font-size: 1rem;
  }
`;

const Settings = () => {
    const { theme, toggleTheme } = useTheme();
    const [discordWebhook, setDiscordWebhook] = useState('');
    const [notificationsEnabled, setNotificationsEnabled] = useState(false);
    const [notificationTime, setNotificationTime] = useState('09:00');

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

    return (
        <SettingsContainer>
            <h1>Settings</h1>

            <h2>Appearance</h2>
            <div className="setting-item">
                <label htmlFor="theme-toggle">Dark Mode</label>
                <label className="theme-switch">
                    <input 
                        type="checkbox" 
                        id="theme-toggle" 
                        checked={theme === 'dark'}
                        onChange={toggleTheme}
                    />
                    <span className="slider"></span>
                </label>
            </div>

            <h2>Notifications</h2>
            <div className="setting-item">
                <label htmlFor="notifications-toggle">Enable Notifications</label>
                <label className="theme-switch">
                    <input 
                        type="checkbox" 
                        id="notifications-toggle" 
                        checked={notificationsEnabled}
                        onChange={handleNotificationsToggle}
                    />
                    <span className="slider"></span>
                </label>
            </div>
            {notificationsEnabled && (
                <div className="setting-item">
                    <label htmlFor="notification-time">Notification Time</label>
                    <div className="time-picker">
                        <input 
                            type="time" 
                            id="notification-time" 
                            value={notificationTime}
                            onChange={handleNotificationTimeChange}
                        />
                    </div>
                </div>
            )}

            <h2>Integrations</h2>
            <div className="setting-item">
                <label htmlFor="discord-webhook">Discord Webhook URL</label>
                <input 
                    type="text" 
                    id="discord-webhook" 
                    className="input-field"
                    placeholder="Enter Discord Webhook URL"
                    value={discordWebhook}
                    onChange={handleWebhookChange}
                />
            </div>
        </SettingsContainer>
    );
};

export default Settings;
