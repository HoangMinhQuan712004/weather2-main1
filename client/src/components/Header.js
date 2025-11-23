import React, { useState } from 'react';
import styled from 'styled-components';
import { motion } from 'framer-motion';
import { 
  FiSearch, 
  FiMapPin, 
  FiHeart, 
  FiUser, 
  FiLogOut,
  FiMenu,
  FiX,
  FiSettings,
  FiMoon,
  FiSun
} from 'react-icons/fi';
import { FaDiscord } from 'react-icons/fa';
import { useNavigate } from 'react-router-dom';
import { useTheme } from '../contexts/ThemeContext';

// Vùng trigger để kích hoạt header khi hover
const HoverTrigger = styled.div`
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  height: 30px;
  z-index: 999;
  
  /* Debug - xóa dòng này sau khi test */
  /* background: rgba(255, 0, 0, 0.1); */
`;

const HeaderContainer = styled.header`
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  z-index: 1000;
  padding: 20px 40px;
  background: var(--header-background);
  backdrop-filter: blur(10px);
  border-bottom: 1px solid var(--border-color);
  transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  
  /* Mặc định ẩn lên trên */
  transform: translateY(-100%);
  
  /* Hiện xuống khi có class 'visible' */
  &.visible {
    transform: translateY(0);
  }
  
  @media (max-width: 768px) {
    padding: 15px 20px;
  }
`;

const HeaderContent = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  max-width: 1200px;
  margin: 0 auto;
`;

const Logo = styled.div`
  display: flex;
  align-items: center;
  color: var(--text-color);
  font-size: 1.8rem;
  font-weight: bold;
  text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.3);
  
  span {
    margin-left: 8px;
    font-size: 1.2rem;
    color: #FFD700;
  }
`;

const SearchBar = styled.div`
  flex: 1;
  max-width: 400px;
  margin: 0 20px;
  position: relative;
  
  @media (max-width: 768px) {
    display: none;
  }
`;

const SearchInput = styled.input`
  width: 100%;
  padding: 12px 20px 12px 45px;
  border: 1px solid var(--border-color);
  border-radius: 25px;
  background: var(--header-background);
  color: var(--text-color);
  font-size: 16px;
  transition: all 0.3s ease;

  &::placeholder {
    color: var(--text-color);
  }

  &:focus {
    outline: none;
    border-color: rgba(255, 255, 255, 0.5);
    background: rgba(255, 255, 255, 0.15);
  }
`;

const ActionButtons = styled.div`
  display: flex;
  align-items: center;
  gap: 15px;
  
  @media (max-width: 768px) {
    gap: 10px;
  }
`;

const Button = styled.button`
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 15px;
  background: var(--header-background);
  border: 1px solid var(--border-color);
  border-radius: 10px;
  color: var(--text-color);
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.3s ease;

  &:hover {
    background: rgba(255, 255, 255, 0.2);
    transform: translateY(-1px);
  }

  @media (max-width: 768px) {
    padding: 8px 12px;
    font-size: 12px;
    
    span {
      display: none;
    }
  }
`;

const UserMenu = styled.div`
  position: relative;
`;

const UserButton = styled.button`
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 15px;
  background: var(--header-background);
  border: 1px solid var(--border-color);
  border-radius: 10px;
  color: var(--text-color);
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.3s ease;

  &:hover {
    background: rgba(255, 255, 255, 0.2);
  }
`;

const DropdownMenu = styled(motion.div)`
  position: absolute;
  top: 100%;
  right: 0;
  margin-top: 10px;
  background: var(--card-background);
  backdrop-filter: blur(10px);
  border: 1px solid var(--border-color);
  border-radius: 10px;
  padding: 10px 0;
  min-width: 200px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
`;

const DropdownItem = styled.button`
  width: 100%;
  padding: 12px 20px;
  background: none;
  border: none;
  color: var(--text-color);
  font-size: 14px;
  text-align: left;
  cursor: pointer;
  transition: background 0.2s ease;
  display: flex;
  align-items: center;
  gap: 10px;

  &:hover {
    background: rgba(0, 0, 0, 0.05);
  }
`;

const MobileMenuButton = styled.button`
  display: none;
  background: none;
  border: none;
  color: var(--text-color);
  font-size: 24px;
  cursor: pointer;
  
  @media (max-width: 768px) {
    display: block;
  }
`;

const MobileMenu = styled(motion.div)`
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.8);
  backdrop-filter: blur(10px);
  z-index: 1001;
  display: none;
  
  @media (max-width: 768px) {
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    gap: 20px;
  }
`;

const MobileMenuContent = styled.div`
  background: var(--card-background);
  backdrop-filter: blur(10px);
  border: 1px solid var(--border-color);
  border-radius: 20px;
  padding: 40px;
  width: 90%;
  max-width: 400px;
`;

const SearchIcon = styled.div`
  position: absolute;
  left: 15px;
  top: 50%;
  transform: translateY(-50%);
  color: var(--text-color);
  display: flex;
  align-items: center;
  font-size: 18px;
  pointer-events: none;
`;

const CloseButton = styled.button`
  position: absolute;
  top: 20px;
  right: 20px;
  background: none;
  border: none;
  color: var(--text-color);
  font-size: 24px;
  cursor: pointer;
`;

const ThemeToggle = styled.button`
  display: flex;
  align-items: center;
  justify-content: center;
  width: 40px;
  height: 40px;
  background: var(--transparent-bg);
  border: 1px solid var(--border-color);
  border-radius: 10px;
  color: var(--text-color);
  cursor: pointer;
  font-size: 18px;
  transition: all var(--transition-fast);

  &:hover {
    background: var(--hover-bg);
    transform: rotate(20deg);
  }
  
  @media (max-width: 768px) {
    width: 36px;
    height: 36px;
    font-size: 16px;
  }
`;

const Header = ({ 
  onSearchClick, 
  onFavoritesClick, 
  onDiscordClick,
  onLocationClick, 
  user, 
  onLogout 
}) => {
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [showMobileMenu, setShowMobileMenu] = useState(false);
  const [isHeaderVisible, setIsHeaderVisible] = useState(false);
  const navigate = useNavigate();
  const { theme, toggleTheme } = useTheme();

  const handleUserMenuToggle = () => {
    setShowUserMenu(!showUserMenu);
  };

  const handleLogout = () => {
    onLogout();
    setShowUserMenu(false);
  };

  const handleSettingsClick = () => {
    navigate('/settings');
    setShowUserMenu(false);
  };

  const handleMouseEnter = () => {
    setIsHeaderVisible(true);
  };

  const handleMouseLeave = () => {
    setIsHeaderVisible(false);
  };

  return (
    <>
      {/* Vùng trigger để kích hoạt header */}
      <HoverTrigger 
        onMouseEnter={handleMouseEnter}
      />
      
      <HeaderContainer 
        className={isHeaderVisible ? 'visible' : ''}
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
      >
        <HeaderContent>
          <Logo>
            WW<span>⚡</span>
          </Logo>

          <SearchBar>
            <SearchIcon>
              <FiSearch />
            </SearchIcon>
            <SearchInput
              placeholder="Search Location..."
              onClick={onSearchClick}
              readOnly
            />
          </SearchBar>

          <ActionButtons>
            <Button onClick={onLocationClick}>
              <FiMapPin />
              <span>Location</span>
            </Button>

            <Button onClick={onFavoritesClick}>
              <FiHeart />
              <span>Favorites</span>
            </Button>

            <Button onClick={onDiscordClick}>
              <FaDiscord />
              <span>Discord</span>
            </Button>

            <ThemeToggle onClick={toggleTheme} title={`Switch to ${theme === 'light' ? 'dark' : 'light'} mode`}>
              {theme === 'light' ? <FiMoon /> : <FiSun />}
            </ThemeToggle>

            <UserMenu>
              <UserButton onClick={handleUserMenuToggle}>
                <FiUser />
                <span>{user?.fullName}</span>
              </UserButton>

              {showUserMenu && (
                <DropdownMenu
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  transition={{ duration: 0.2 }}
                >
                  <DropdownItem onClick={handleSettingsClick}>
                    <FiSettings />
                    Settings
                  </DropdownItem>
                  <DropdownItem onClick={handleLogout}>
                    <FiLogOut />
                    Logout
                  </DropdownItem>
                </DropdownMenu>
              )}
            </UserMenu>

            <MobileMenuButton onClick={() => setShowMobileMenu(true)}>
              <FiMenu />
            </MobileMenuButton>
          </ActionButtons>
        </HeaderContent>

        {showMobileMenu && (
          <MobileMenu
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setShowMobileMenu(false)}
          >
            <MobileMenuContent onClick={(e) => e.stopPropagation()}>
              <CloseButton onClick={() => setShowMobileMenu(false)}>
                <FiX />
              </CloseButton>
              
              <div style={{ color: 'white', textAlign: 'center', marginBottom: '30px' }}>
                <h2>Welcome, {user?.username}!</h2>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
                <Button onClick={() => { onSearchClick(); setShowMobileMenu(false); }}>
                  <FiSearch />
                  <span>Search Location</span>
                </Button>

                <Button onClick={() => { onFavoritesClick(); setShowMobileMenu(false); }}>
                  <FiHeart />
                  <span>Favorites</span>
                </Button>

                <Button onClick={() => { onDiscordClick(); setShowMobileMenu(false); }}>
                  <FaDiscord />
                  <span>Discord</span>
                </Button>

                <Button onClick={() => { onLocationClick(); setShowMobileMenu(false); }}>
                  <FiMapPin />
                  <span>Current Location</span>
                </Button>

                <Button onClick={() => { toggleTheme(); setShowMobileMenu(false); }}>
                  {theme === 'light' ? <FiMoon /> : <FiSun />}
                  <span>{theme === 'light' ? 'Dark Mode' : 'Light Mode'}</span>
                </Button>

                <Button onClick={() => { handleSettingsClick(); setShowMobileMenu(false); }}>
                  <FiSettings />
                  <span>Settings</span>
                </Button>

                <Button onClick={() => { handleLogout(); setShowMobileMenu(false); }}>
                  <FiLogOut />
                  <span>Logout</span>
                </Button>
              </div>
            </MobileMenuContent>
          </MobileMenu>
        )}
      </HeaderContainer>
    </>
  );
};

export default Header;