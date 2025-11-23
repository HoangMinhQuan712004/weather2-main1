import React, { useState, useEffect, useRef, useCallback } from 'react';
import styled from 'styled-components';
import { motion, AnimatePresence } from 'framer-motion';
import { FiSearch, FiX, FiMapPin, FiClock, FiHeart } from 'react-icons/fi';
import { useWeather } from '../contexts/WeatherContext';
import { useAuth } from '../contexts/AuthContext';
import { useDebounce } from '../hooks/useDebounce';

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

const SearchContainer = styled.div`
  padding: 20px;
`;

const SearchInput = styled.input`
  width: 100%;
  padding: 15px 20px 15px 50px;
  border: 1px solid rgba(255, 255, 255, 0.3);
  border-radius: 15px;
  background: rgba(255, 255, 255, 0.1);
  color: white;
  font-size: 16px;
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

const SearchIcon = styled.div`
  position: absolute;
  left: 20px;
  top: 50%;
  transform: translateY(-50%);
  color: rgba(255, 255, 255, 0.7);
  font-size: 18px;
`;

const SearchWrapper = styled.div`
  position: relative;
  margin-bottom: 20px;
`;

const ResultsContainer = styled.div`
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

const ResultItem = styled(motion.div)`
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

const ResultIcon = styled.div`
  font-size: 1.2rem;
  color: rgba(255, 255, 255, 0.8);
`;

const ResultContent = styled.div`
  flex: 1;
  color: white;
`;

const ResultName = styled.div`
  font-size: 1.1rem;
  font-weight: 500;
  margin-bottom: 5px;
`;

const ResultCountry = styled.div`
  font-size: 0.9rem;
  opacity: 0.8;
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
`;

const HistorySection = styled.div`
  margin-top: 20px;
`;

const SectionTitle = styled.h3`
  color: white;
  font-size: 1.1rem;
  font-weight: 600;
  margin-bottom: 15px;
  display: flex;
  align-items: center;
  gap: 10px;
`;

const ClearHistoryButton = styled.button`
  background: none;
  border: none;
  color: rgba(255, 255, 255, 0.7);
  font-size: 0.9rem;
  cursor: pointer;
  text-decoration: underline;
  margin-left: auto;

  &:hover {
    color: white;
  }
`;

const EmptyState = styled.div`
  text-align: center;
  color: rgba(255, 255, 255, 0.7);
  padding: 40px 20px;
  
  p {
    margin-bottom: 10px;
  }
`;

const LoadingSpinner = styled.div`
  display: flex;
  justify-content: center;
  align-items: center;
  padding: 20px;
  
  &::after {
    content: '';
    width: 20px;
    height: 20px;
    border: 2px solid rgba(255, 255, 255, 0.3);
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

const SearchModal = ({ onClose }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [searchHistory, setSearchHistory] = useState([]);
  const [searchError, setSearchError] = useState(null);
  const inputRef = useRef(null);
  
  // Debounce search query to avoid excessive API calls (800ms to prevent rapid requests)
  const debouncedSearchQuery = useDebounce(searchQuery, 800);
  
  const { 
    searchResults, 
    loading, 
    searchLoading,
    searchCities, 
    getCurrentWeather,
    getForecast,
    getWeatherBundle,
    addToSearchHistory,
    getSearchHistory,
    clearSearchHistory,
    clearSearchResults
  } = useWeather();

  const { user } = useAuth();

  const loadSearchHistory = useCallback(async () => {
    try {
      // Only load if we don't have history yet
      if (searchHistory.length === 0) {
        const history = await getSearchHistory();
        setSearchHistory(history);
      }
    } catch (error) {
      console.error('Failed to load search history:', error);
    }
  }, [getSearchHistory, searchHistory.length]);

  useEffect(() => {
    // Focus input when modal opens
    if (inputRef.current) {
      inputRef.current.focus();
    }

    // Load search history only if not already loaded
    loadSearchHistory();
  }, [loadSearchHistory]);

  const handleSearch = useCallback(async (query) => {
    if (query.trim().length < 2) {
      console.log('Query too short, clearing results');
      setSearchError(null);
      return;
    }
    
    console.log('handleSearch called with:', query);
    try {
      setSearchError(null);
      const results = await searchCities(query);
      console.log('Search completed with results:', results);
    } catch (error) {
      console.error('Search failed:', error);
      // Normalize error message for display
      const apiError = error?.response?.data?.error || error?.response?.data?.message || error?.message;
      if (apiError === 'API_KEY_MISSING' || /Invalid API key/i.test(apiError || '')) {
        setSearchError('Weather service API key is invalid or not configured. Contact the administrator.');
      } else {
        setSearchError('Search failed. Please try again.');
      }
    }
  }, [searchCities]);

  // Effect to handle debounced search
  useEffect(() => {
    if (debouncedSearchQuery.trim().length >= 2) {
      handleSearch(debouncedSearchQuery);
    } else if (debouncedSearchQuery.trim().length === 0) {
      // Clear results when search is empty
      clearSearchResults();
      setSearchError(null);
    }
  }, [debouncedSearchQuery, handleSearch, clearSearchResults]);

  const handleInputChange = (e) => {
    const value = e.target.value;
    setSearchQuery(value);
  };

  const handleCitySelect = async (city) => {
    try {
      // Get weather for selected city. Use bundled fetch if available to
      // reduce duplicate requests; otherwise fetch both in parallel.
      if (typeof getWeatherBundle === 'function') {
        await getWeatherBundle(city.lat, city.lon);
      } else {
        await Promise.all([
          getCurrentWeather(city.lat, city.lon),
          getForecast(city.lat, city.lon)
        ]);
      }
      
      // Add to search history
      await addToSearchHistory(city.name, city.country);
      
      // Close modal
      onClose();
    } catch (error) {
      console.error('Failed to get weather for city:', error);
    }
  };

  const handleHistorySelect = async (historyItem) => {
    try {
      // Search for the city from history
      const results = await searchCities(historyItem.city);
      if (results && results.length > 0) {
        // Select the first result
        await handleCitySelect(results[0]);
      } else {
        // If no results, just do a search to show "not found"
        await handleSearch(historyItem.city);
      }
    } catch (error) {
      console.error('Failed to select from history:', error);
    }
  };

  const handleClearHistory = async () => {
    try {
      await clearSearchHistory();
      setSearchHistory([]);
    } catch (error) {
      console.error('Failed to clear history:', error);
    }
  };


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
            <ModalTitle>Search Location</ModalTitle>
            <CloseButton onClick={onClose}>
              <FiX />
            </CloseButton>
          </ModalHeader>

          <SearchContainer>
            <SearchWrapper>
              <SearchIcon>
                <FiSearch />
              </SearchIcon>
              <SearchInput
                ref={inputRef}
                type="text"
                placeholder="Search for a city..."
                value={searchQuery}
                onChange={handleInputChange}
              />
            </SearchWrapper>

            <ResultsContainer>
              {searchLoading && <LoadingSpinner />}
              
              {!searchLoading && searchResults.length > 0 && (
                <div>
                  {searchResults.map((city, index) => (
                    <ResultItem
                      key={index}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: index * 0.1 }}
                      onClick={() => handleCitySelect(city)}
                    >
                      <ResultIcon>
                        <FiMapPin />
                      </ResultIcon>
                      <ResultContent>
                        <ResultName>{city.name}</ResultName>
                        <ResultCountry>{city.country}</ResultCountry>
                      </ResultContent>
                    </ResultItem>
                  ))}
                </div>
              )}

              {!searchLoading && searchResults.length === 0 && searchQuery.length >= 2 && (
                searchError ? (
                  <EmptyState>
                    <p>{searchError}</p>
                  </EmptyState>
                ) : (
                  <EmptyState>
                    <p>No cities found for "{searchQuery}"</p>
                    <p>Try a different search term</p>
                  </EmptyState>
                )
              )}

              {!searchLoading && searchQuery.length < 2 && searchHistory.length > 0 && (
                <HistorySection>
                  <SectionTitle>
                    <FiClock />
                    Recent Searches
                    <ClearHistoryButton onClick={handleClearHistory}>
                      Clear
                    </ClearHistoryButton>
                  </SectionTitle>
                  
                  {searchHistory.slice(0, 5).map((historyItem, index) => (
                    <ResultItem
                      key={index}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: index * 0.1 }}
                      onClick={() => handleHistorySelect(historyItem)}
                    >
                      <ResultIcon>
                        <FiClock />
                      </ResultIcon>
                      <ResultContent>
                        <ResultName>{historyItem.city}</ResultName>
                        <ResultCountry>{historyItem.country}</ResultCountry>
                      </ResultContent>
                    </ResultItem>
                  ))}
                </HistorySection>
              )}

              {!searchLoading && searchQuery.length < 2 && searchHistory.length === 0 && (
                <EmptyState>
                  <p>Start typing to search for cities</p>
                  <p>Your recent searches will appear here</p>
                </EmptyState>
              )}
            </ResultsContainer>
          </SearchContainer>
        </ModalContent>
      </ModalOverlay>
    </AnimatePresence>
  );
};

export default SearchModal;
