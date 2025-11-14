import React, { useState, useEffect } from 'react';
import styled from 'styled-components';
import { motion, AnimatePresence } from 'framer-motion';
import { FiX, FiMapPin, FiTrash2, FiHeart } from 'react-icons/fi';
import { useWeather } from '../contexts/WeatherContext';
import { useAuth } from '../contexts/AuthContext';

const ModalOverlay = styled(motion.div)`
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.8);
  backdrop-filter: blur(10px);
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
`;

const ModalContent = styled(motion.div)`
  background: rgba(255, 255, 255, 0.1);
  backdrop-filter: blur(20px);
  border: 1px solid rgba(255, 255, 255, 0.2);
  border-radius: 20px;
  width: 100%;
  max-width: 500px;
  max-height: 80vh;
  overflow: hidden;
`;

const ModalHeader = styled.div`
  padding: 20px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.2);
  display: flex;
  align-items: center;
  justify-content: space-between;
`;

const ModalTitle = styled.h2`
  color: white;
  font-size: 1.5rem;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 10px;
`;

const CloseButton = styled.button`
  background: none;
  border: none;
  color: white;
  font-size: 24px;
  cursor: pointer;
  padding: 5px;
  border-radius: 50%;
  transition: background 0.3s ease;

  &:hover {
    background: rgba(255, 255, 255, 0.1);
  }
`;

const FavoritesContainer = styled.div`
  padding: 20px;
  max-height: 400px;
  overflow-y: auto;
  
  &::-webkit-scrollbar {
    width: 6px;
  }
  
  &::-webkit-scrollbar-track {
    background: rgba(255, 255, 255, 0.1);
    border-radius: 3px;
  }
  
  &::-webkit-scrollbar-thumb {
    background: rgba(255, 255, 255, 0.3);
    border-radius: 3px;
  }
`;

const FavoriteItem = styled(motion.div)`
  display: flex;
  align-items: center;
  gap: 15px;
  padding: 15px;
  background: rgba(255, 255, 255, 0.1);
  border-radius: 15px;
  margin-bottom: 10px;
  cursor: pointer;
  transition: all 0.3s ease;
  border: 1px solid transparent;

  &:hover {
    background: rgba(255, 255, 255, 0.15);
    border-color: rgba(255, 255, 255, 0.3);
    transform: translateY(-2px);
  }
`;

const FavoriteIcon = styled.div`
  font-size: 1.2rem;
  color: rgba(255, 255, 255, 0.8);
`;

const FavoriteContent = styled.div`
  flex: 1;
  color: white;
`;

const FavoriteName = styled.div`
  font-size: 1.1rem;
  font-weight: 500;
  margin-bottom: 5px;
`;

const FavoriteCountry = styled.div`
  font-size: 0.9rem;
  opacity: 0.8;
`;

const FavoriteActions = styled.div`
  display: flex;
  gap: 10px;
`;

const ActionButton = styled.button`
  background: rgba(255, 255, 255, 0.1);
  border: 1px solid rgba(255, 255, 255, 0.3);
  border-radius: 8px;
  color: white;
  padding: 8px 12px;
  cursor: pointer;
  transition: all 0.3s ease;
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 0.9rem;

  &:hover {
    background: rgba(255, 255, 255, 0.2);
  }

  &.danger:hover {
    background: rgba(255, 107, 107, 0.2);
    border-color: rgba(255, 107, 107, 0.5);
  }
`;

const EmptyState = styled.div`
  text-align: center;
  color: rgba(255, 255, 255, 0.7);
  padding: 40px 20px;
  
  .icon {
    font-size: 3rem;
    margin-bottom: 20px;
    opacity: 0.5;
  }
  
  h3 {
    font-size: 1.2rem;
    margin-bottom: 10px;
  }
  
  p {
    margin-bottom: 10px;
  }
`;

const LoadingSpinner = styled.div`
  display: flex;
  justify-content: center;
  align-items: center;
  padding: 40px;
  
  &::after {
    content: '';
    width: 30px;
    height: 30px;
    border: 3px solid rgba(255, 255, 255, 0.3);
    border-radius: 50%;
    border-top-color: white;
    animation: spin 1s linear infinite;
  }
  
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
`;

const FavoritesModal = ({ onClose }) => {
  const [favorites, setFavorites] = useState([]);
  const [loading, setLoading] = useState(true);
  
  const { 
    getCurrentWeather,
    getForecast,
    removeFromFavorites,
    addToFavorites,
    favoriteCities
  } = useWeather();

  const { user } = useAuth();

  // Keep local favorites in sync with WeatherContext.favoriteCities (updates when add/remove happen)
  useEffect(() => {
    // Only set loading if we don't have favorites data yet
    if (favorites.length === 0) {
      setLoading(true);
    }
    
    if (Array.isArray(favoriteCities) && favoriteCities.length > 0) {
      setFavorites(favoriteCities);
    } else if (user?.favoriteCities) {
      // fallback to user data from AuthContext if available
      setFavorites(user.favoriteCities || []);
    } else {
      setFavorites([]);
    }
    setLoading(false);
  }, [favoriteCities, user, favorites.length]);

  const handleFavoriteSelect = async (favorite) => {
    try {
      // Get weather for selected favorite city
      await getCurrentWeather(favorite.lat, favorite.lon);
      await getForecast(favorite.lat, favorite.lon);
      
      // Close modal
      onClose();
    } catch (error) {
      console.error('Failed to get weather for favorite:', error);
    }
  };

  const handleRemoveFavorite = React.useCallback(async (favoriteId) => {
    try {
      setLoading(true);
      await removeFromFavorites(favoriteId);
      // WeatherContext will update `favoriteCities` and the effect above will sync local state.
    } catch (error) {
      console.error('Failed to remove favorite:', error);
    } finally {
      setLoading(false);
    }
  }, [removeFromFavorites]);

  return (
    <AnimatePresence>
      <ModalOverlay
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={onClose}
      >
        <ModalContent
          initial={{ opacity: 0, scale: 0.9, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.9, y: 20 }}
          onClick={(e) => e.stopPropagation()}
        >
          <ModalHeader>
            <ModalTitle>
              <FiHeart />
              Favorite Cities
            </ModalTitle>
            <CloseButton onClick={onClose}>
              <FiX />
            </CloseButton>
          </ModalHeader>

          <FavoritesContainer>
            {loading ? (
              <LoadingSpinner />
            ) : favorites.length > 0 ? (
              <div>
                {favorites.map((favorite, index) => (
                  <FavoriteItem
                    key={favorite._id || index}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.1 }}
                    onClick={() => handleFavoriteSelect(favorite)}
                  >
                    <FavoriteIcon>
                      <FiMapPin />
                    </FavoriteIcon>
                    <FavoriteContent>
                      <FavoriteName>{favorite.name}</FavoriteName>
                      <FavoriteCountry>{favorite.country}</FavoriteCountry>
                    </FavoriteContent>
                    <FavoriteActions>
                      <ActionButton
                        className="danger"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleRemoveFavorite(favorite._id);
                        }}
                      >
                        <FiTrash2 />
                      </ActionButton>
                    </FavoriteActions>
                  </FavoriteItem>
                ))}
              </div>
            ) : (
              <EmptyState>
                <div className="icon">
                  <FiHeart />
                </div>
                <h3>No favorite cities yet</h3>
                <p>Add cities to your favorites to quickly access their weather</p>
                <p>Search for a city and click the heart icon to add it</p>
              </EmptyState>
            )}
          </FavoritesContainer>
        </ModalContent>
      </ModalOverlay>
    </AnimatePresence>
  );
};

export default FavoritesModal;
