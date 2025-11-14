import React from 'react';
import styled from 'styled-components';

const SpinnerContainer = styled.div`
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100vh;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
`;

const Spinner = styled.div`
  width: 50px;
  height: 50px;
  border: 5px solid rgba(255, 255, 255, 0.3);
  border-radius: 50%;
  border-top-color: #fff;
  animation: spin 1s ease-in-out infinite;

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
`;

const LoadingText = styled.p`
  color: white;
  margin-top: 20px;
  font-size: 18px;
  font-weight: 500;
`;

const LoadingSpinner = () => {
  return (
    <SpinnerContainer>
      <div style={{ textAlign: 'center' }}>
        <Spinner />
        <LoadingText>Loading...</LoadingText>
      </div>
    </SpinnerContainer>
  );
};

export default LoadingSpinner;
