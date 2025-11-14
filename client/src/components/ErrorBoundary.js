import React from 'react';
import styled from 'styled-components';
import { FiAlertTriangle, FiRefreshCw, FiWifi, FiWifiOff } from 'react-icons/fi';
import { testServerConnection } from '../utils/connectionTest';

const ErrorContainer = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 400px;
  padding: 40px;
  text-align: center;
  color: white;
`;

const ErrorIcon = styled.div`
  font-size: 4rem;
  color: #ff6b6b;
  margin-bottom: 20px;
`;

const ErrorTitle = styled.h2`
  font-size: 1.8rem;
  font-weight: 600;
  margin-bottom: 15px;
  color: white;
`;

const ErrorMessage = styled.p`
  font-size: 1.1rem;
  opacity: 0.8;
  margin-bottom: 30px;
  max-width: 500px;
  line-height: 1.6;
`;

const RetryButton = styled.button`
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 24px;
  background: rgba(255, 255, 255, 0.1);
  border: 1px solid rgba(255, 255, 255, 0.3);
  border-radius: 10px;
  color: white;
  font-size: 1rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.3s ease;

  &:hover {
    background: rgba(255, 255, 255, 0.2);
    transform: translateY(-2px);
  }
`;

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { 
      hasError: false, 
      error: null, 
      errorInfo: null,
      isNetworkError: false,
      connectionStatus: 'unknown'
    };
  }

  static getDerivedStateFromError(error) {
    // Check if it's a network-related error
    const isNetworkError = error?.message?.includes('Network Error') || 
                          error?.message?.includes('fetch') ||
                          error?.code === 'NETWORK_ERROR' ||
                          error?.code === 'ECONNREFUSED';
    
    return { hasError: true, isNetworkError };
  }

  componentDidCatch(error, errorInfo) {
    this.setState({
      error: error,
      errorInfo: errorInfo
    });
    
    // Log error to console in development
    if (process.env.NODE_ENV === 'development') {
      console.error('ErrorBoundary caught an error:', error, errorInfo);
    }
  }

  handleRetry = async () => {
    // Test server connection before retrying
    const result = await testServerConnection();
    this.setState({ 
      hasError: false, 
      error: null, 
      errorInfo: null,
      connectionStatus: result.success ? 'connected' : 'disconnected'
    });
  };

  checkConnection = async () => {
    const result = await testServerConnection();
    this.setState({ 
      connectionStatus: result.success ? 'connected' : 'disconnected'
    });
  };

  render() {
    if (this.state.hasError) {
      const { isNetworkError, connectionStatus } = this.state;
      
      return (
        <ErrorContainer>
          <ErrorIcon>
            {isNetworkError ? <FiWifiOff /> : <FiAlertTriangle />}
          </ErrorIcon>
          <ErrorTitle>
            {isNetworkError ? 'Connection Problem' : 'Something went wrong'}
          </ErrorTitle>
          <ErrorMessage>
            {isNetworkError 
              ? 'Unable to connect to the server. Please check your internet connection and make sure the server is running.'
              : 'We\'re sorry, but something unexpected happened. Please try refreshing the page or contact support if the problem persists.'
            }
          </ErrorMessage>
          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', justifyContent: 'center' }}>
            <RetryButton onClick={this.handleRetry}>
              <FiRefreshCw />
              Try Again
            </RetryButton>
            {isNetworkError && (
              <RetryButton onClick={this.checkConnection}>
                {connectionStatus === 'connected' ? <FiWifi /> : <FiWifiOff />}
                Check Connection
              </RetryButton>
            )}
          </div>
        </ErrorContainer>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
