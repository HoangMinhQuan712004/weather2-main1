import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { useWeather } from '../contexts/WeatherContext';
import styled from 'styled-components';
import { motion, AnimatePresence } from 'framer-motion';
import Header from '../components/Header';
import WeatherDisplay from '../components/WeatherDisplay';
import SearchModal from '../components/SearchModal';
import FavoritesModal from '../components/FavoritesModal';
import DiscordSettings from '../components/DiscordSettings';
import WeatherTrendChart from '../components/WeatherTrendChart';
import WeatherMap from '../components/WeatherMap';
import LoadingSpinner from '../components/LoadingSpinner';

const weatherGradients = {
  clear: 'linear-gradient(135deg, #87CEEB 0%, #98D8E8 100%)',
  clouds: 'linear-gradient(135deg, #B0C4DE 0%, #D3D3D3 100%)',
  rain: 'linear-gradient(135deg, #4682B4 0%, #5F9EA0 100%)',
  drizzle: 'linear-gradient(135deg, #4682B4 0%, #5F9EA0 100%)',
  snow: 'linear-gradient(135deg, #E6E6FA 0%, #F0F8FF 100%)',
  thunderstorm: 'linear-gradient(135deg, #2F4F4F 0%, #708090 100%)',
  mist: 'linear-gradient(135deg, #C0C0C0 0%, #DCDCDC 100%)',
  fog: 'linear-gradient(135deg, #C0C0C0 0%, #DCDCDC 100%)',
  default: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
};

const HomeContainer = styled.div`
  min-height: 100vh;
  background: ${props => {
    const weatherType = props.weather?.current?.weather?.main?.toLowerCase();
    const gradient = weatherGradients[weatherType] || weatherGradients.default;
    return gradient; // Keep weather-specific gradients
  }};
  transition: background 0.5s ease;
  position: relative;
  overflow: hidden;
  color: var(--text-color-light); /* Apply text color from theme */
`;

const SnowEffect = styled.div`
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  pointer-events: none;
  z-index: 1;
  
  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-image: 
      radial-gradient(2px 2px at 20px 30px, white, transparent),
      radial-gradient(2px 2px at 40px 70px, white, transparent),
      radial-gradient(1px 1px at 90px 40px, white, transparent),
      radial-gradient(1px 1px at 130px 80px, white, transparent),
      radial-gradient(2px 2px at 160px 30px, white, transparent);
    background-repeat: repeat;
    background-size: 200px 100px;
    animation: snow 10s linear infinite;
    opacity: ${props => props.weather?.current?.weather?.main === 'Snow' ? 0.8 : 0};
  }
  
  @keyframes snow {
    from {
      transform: translateY(-100px);
    }
    to {
      transform: translateY(100vh);
    }
  }
`;

const MainContent = styled.div`
  position: relative;
  z-index: 2;
  display: flex;
  /* account for fixed header (~80px) so panels have stable height */
  min-height: calc(100vh - 80px);
  height: calc(100vh - 80px);

  @media (max-width: 768px) {
    flex-direction: column;
    min-height: auto;
    height: auto;
  }
`;

const LeftPanel = styled(motion.div)`
  flex: 2;
  padding: 40px;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  color: var(--text-color-light); /* Apply text color from theme */
  
  @media (max-width: 768px) {
    padding: 20px;
    flex: 1;
  }
`;

const RightPanel = styled(motion.div)`
  flex: 1;
  background: var(--card-background-light);
  backdrop-filter: blur(10px);
  border-left: 1px solid var(--border-color-light);
  padding: 40px;
  overflow-y: auto;
  /* keep panel height tied to MainContent to avoid reflow */
  position: relative;
  height: 100%;
  box-sizing: border-box;

  @media (max-width: 768px) {
    border-left: none;
    border-top: 1px solid var(--border-color-light);
    padding: 20px;
    position: relative;
    height: auto;
  }
`;

const WelcomeMessage = styled.div`
  text-align: center;
  margin-bottom: 40px;
  
  h1 {
    font-size: 3rem;
    font-weight: bold;
    margin-bottom: 10px;
    text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.3);
    color: var(--text-color-light); /* Apply text color from theme */
  }
  
  p {
    font-size: 1.2rem;
    opacity: 0.9;
    color: var(--text-color-light); /* Apply text color from theme */
  }
`;

const GetStartedButton = styled.button`
  background: var(--header-background-light);
  border: 2px solid var(--border-color-light);
  border-radius: 15px;
  padding: 15px 30px;
  color: var(--text-color-light);
  font-size: 1.1rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.3s ease;
  
  &:hover {
    background: rgba(255, 255, 255, 0.3);
    transform: translateY(-2px);
  }
`;

const Home = () => {
  const { user, logout } = useAuth();
  const { 
    currentWeather, 
    forecast, 
    loading, 
    getGeolocationWeather,
    getCurrentWeather,
    getForecast 
  } = useWeather();
  
  const [showSearchModal, setShowSearchModal] = useState(false);
  const [showFavoritesModal, setShowFavoritesModal] = useState(false);
  const [showDiscordSettings, setShowDiscordSettings] = useState(false);

  useEffect(() => {
    // Try to get weather for user's last location or current location
    const loadInitialWeather = async () => {
      try {
        // Only load if we don't already have weather data
        if (!currentWeather) {
          if (user?.lastLocation) {
            // Use geolocation endpoint for better performance (single API call)
            await getGeolocationWeather();
          } else {
            await getGeolocationWeather();
          }
        }
      } catch (error) {
        console.error('Failed to load initial weather:', error);
      }
    };

    // Add a small delay to prevent race conditions
    const timeoutId = setTimeout(loadInitialWeather, 100);
    return () => clearTimeout(timeoutId);
  }, [user, currentWeather, getGeolocationWeather]);

  const handleGetCurrentLocation = async () => {
    try {
      const result = await getGeolocationWeather();
      console.log('Location weather loaded:', result);
    } catch (error) {
      console.error('Failed to get current location weather:', error);
    }
  };

  if (loading && !currentWeather) {
    return <LoadingSpinner />;
  }

  return (
    <HomeContainer weather={currentWeather}>
      <SnowEffect weather={currentWeather} />
      
      <Header 
        onSearchClick={() => setShowSearchModal(true)}
        onFavoritesClick={() => setShowFavoritesModal(true)}
        onDiscordClick={() => setShowDiscordSettings(prevState => !prevState)}
        onLocationClick={handleGetCurrentLocation}
        user={user}
        onLogout={logout}
      />

      <MainContent>
        <LeftPanel
          layout
          initial={{ opacity: 0, x: -50 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.5 }}
        >
          {currentWeather ? (
            <WeatherDisplay 
              weather={currentWeather}
              forecast={forecast}
            />
          ) : (
            <div>
              <WelcomeMessage>
                <h1>Welcome, {user?.username}!</h1>
                <p>Get started by searching for a city or using your current location</p>
              </WelcomeMessage>
              <GetStartedButton onClick={() => setShowSearchModal(true)}>
                Search for Weather
              </GetStartedButton>
            </div>
          )}
        </LeftPanel>

        <RightPanel
          layout
          initial={{ opacity: 0, x: 50 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
        >
          {/* stable container to avoid reflow; internal content swaps with AnimatePresence */}
          <motion.div layout style={{ minHeight: 560 }}>
            <AnimatePresence mode="wait">
              {showDiscordSettings ? (
                <motion.div
                  key="discord"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  transition={{ duration: 0.25 }}
                >
                  <DiscordSettings />
                </motion.div>
              ) : currentWeather && forecast ? (
                <motion.div
                  key="details"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  transition={{ duration: 0.25 }}
                >
                  <WeatherDisplay 
                    weather={currentWeather}
                    forecast={forecast}
                    isDetailsPanel
                  />
                  {currentWeather?.location?.lat && currentWeather?.location?.lon && (
                    <WeatherTrendChart 
                      lat={currentWeather.location.lat}
                      lon={currentWeather.location.lon}
                    />
                  )}
                  {currentWeather?.location?.lat && currentWeather?.location?.lon && (
                    <WeatherMap 
                      lat={currentWeather.location.lat}
                      lon={currentWeather.location.lon}
                      cityName={currentWeather.location.name}
                    />
                  )}
                </motion.div>
              ) : (
                <motion.div
                  key="placeholder"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  transition={{ duration: 0.25 }}
                >
                  <div style={{ color: 'white', textAlign: 'center', padding: '40px 0' }}>
                    <h3>Weather Details</h3>
                    <p>Search for a city to see detailed weather information</p>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </motion.div>
        </RightPanel>
      </MainContent>

      {showSearchModal && (
        <SearchModal onClose={() => setShowSearchModal(false)} />
      )}

      {showFavoritesModal && (
        <FavoritesModal onClose={() => setShowFavoritesModal(false)} />
      )}
    </HomeContainer>
  );
};

export default Home;